import sys
import json
import time
import signal
from enum import Enum
from fuzzcounter import FuzzCounterArgFuzzer
from src.sniffer.sniffer import Sniffer
from src.sniffer.bltlog_analyzer import BltLogAnalyzer
from src.methods_finder import SendFinder, SweetSpotFinder
from src.frida_hooker.frida_hooker import FridaHooker, FridaRunner
from src.ui.core import ADBDriver
from src.arg_fuzzer.arg_fuzzer import ArgFuzzer
from pysoot.lifter import Lifter
from node_filter.node_filter import NodeFilter

import logging

logging.basicConfig()
log = logging.getLogger("ApkFuzzer")
log.setLevel(logging.DEBUG)

RERAN_RECORD_PATH = '/tmp/reran.log'

class Phase(Enum):
    SETUP = 0
    RERAN = 1
    KEEPALIVE = 2
    MESSAGE_SENDER = 3
    FUZZING_CANDIDATES = 4
    FUZZING = 5

    def __lt__(self, other):
        return self.value < other.value

    def __le__(self, other):
        return self.value <= other.value

    def __gt__(self, other):
        return self.value > other.value

    def __ge__(self, other):
        return self.value >= other.value

    def __eq__(self, other):
        return self.value == other.value

    def __ne__(self, other):
        return not self.value == other.value

@FridaRunner
class IoTFuzzer:
    def __init__(self, config):
        self.config = config
        self.reran_record_path = config['reran_record_path']
        self.senders = config['send_functions'] if 'send_functions' in config else []
        self.automated_senders = []
        self.fuzzing_candidates = config['fuzzing_candidates'] if 'fuzzing_candidates' in config else []
        self.sp = config['sweet_spots'] if 'sweet_spots' in config else []
        self.phase = Phase.SETUP

        self.lifter = None
        if not config['leaf_pickle']:
            log.debug("Building lifter")
            self.create_lifter()

        log.debug("Building node filter")
        self.nf = NodeFilter(self.config, lifter=self.lifter)

        log.debug("Building Reran Object")
        self.adbd = ADBDriver(device_id=config['device_id'])
        log.debug("Done.")

        log.debug("Building Sniffer")
        sniffer_config = {
            'android_ip': config['android_ip'],
            'device_ip': config['device_ip'],
            'ip_hot_spot': config['ip_hot_spot'],
            'pass_ap': config['pass_ap']
            }
        self.sniffer = Sniffer(sniffer_config)
        log.debug("Done.")

        log.debug("Building BltLogAnalyzer")
        self.bltlog_analyzer = BltLogAnalyzer()
        log.debug("Done.")

        log.debug("Building Hooker")
        self.hooker = FridaHooker(config, node_filter=self.nf)
        log.debug("Done.")

        log.debug("Building SendFinder")
        self.send_finder = SendFinder(config, sniffer=self.sniffer, hooker=self.hooker, bltlog_analyzer=self.bltlog_analyzer)
        log.debug("Done.")

        log.debug("Building SweetSpotFinder")
        self.sp_finder = SweetSpotFinder(config, hooker=self.hooker, node_lifter=self.nf)
        log.debug("Done.")

        log.debug("Building ArgFuzzer")
        self.arg_fuzzer = ArgFuzzer(config, hooker=self.hooker)
        log.debug("Done.")
        
        log.debug("Building Fuzz Counter ArgFuzzer")
        self.fuzz_counter_arg_fuzzer = FuzzCounterArgFuzzer(config, hooker=self.hooker)
        log.debug("Done.")

        signal.signal(signal.SIGINT, self.signal_handler)

    def create_lifter(self):
        log.info("Creating Lifter")
        self.lifter = Lifter(self.config['apk_path'], input_format="apk", android_sdk=self.config['android_sdk_platforms'])

    def run_reran(self):
        if not self.reran_record_path:
            self.hooker.spawn_apk_in_device()
            self.adbd.record_ui(RERAN_RECORD_PATH)
            self.reran_record_path = RERAN_RECORD_PATH
            self.hooker.terminate()
        self.adbd.translate_events_log(self.reran_record_path)

    def detect_keep_alive(self):
        self.hooker.start()#leaves=True)
        self.sniffer.detect_keepalive()
        self.hooker.terminate()
        self.bltlog_analyzer.detect_keep_alives()

    def signal_handler(self, sig, _):
        if sig == signal.SIGINT:
            self.terminate()

    def terminate(self):
        log.info("Terminating...")
        if self.phase == Phase.KEEPALIVE:
            self.sniffer.terminate()
        elif self.phase == Phase.MESSAGE_SENDER:
            self.send_finder.terminate()
        elif self.phase == Phase.FUZZING:
            self.arg_fuzzer.terminate()

    def run_reran_phase(self):
        log.info("Recording user interactions")
        self.phase = Phase.RERAN
        self.run_reran()

    def run_message_sender_phase(self):
        log.info("Finding send-message method")
        self.phase = Phase.MESSAGE_SENDER
        starting_time = time.time()
        self.senders = self.send_finder.start(ran_fun=self.adbd.replay_ui_async, lifter=self.lifter, ignore=self.automated_senders)
        elapsed_time = time.time() - starting_time
        with open('/tmp/stats_' + self.config['proc_name'], 'w') as eval_stats:
            eval_stats.write('Time (s): {}\nSenders: {}\n'.format(str(elapsed_time), str(self.senders)))
        log.debug("Possible senders {}".format(str(self.senders)))

    def run_fuzzing_candidates_phase(self):
        log.info("Finding fuzzing candidates")
        self.phase = Phase.FUZZING_CANDIDATES
        if not self.lifter:
            self.create_lifter()
        starting_time = time.time()
        sp = [self.sp_finder.start(s, lifter=self.lifter, ran_fun=self.adbd.replay_ui_async) for s in self.senders]
        self.sp = [x for l in sp for x in l if x]
        elapsed_time = time.time() - starting_time
        with open('/tmp/stats_' + self.config['proc_name'], 'a') as eval_stats:
            eval_stats.write('Time (s): {}\nsweet spots: {}\n'.format(str(elapsed_time), str(self.sp)))
        log.debug("Sweet spots: {}".format(str(self.sp)))

    def run_fuzzing_phase(self):
        log.info("Starting fuzzing")
        self.phase = Phase.FUZZING

        for function_to_fuzz in self.senders:
            self.arg_fuzzer.start(function_to_fuzz, fast_fuzz=True, ran_fun=self.adbd.replay_ui_async, lifter=self.lifter)

        for function_to_fuzz in self.senders:
            self.arg_fuzzer.start(function_to_fuzz, ran_fun=self.adbd.replay_ui_async, lifter=self.lifter)

        for function_to_fuzz in self.sp:
            self.arg_fuzzer.start(function_to_fuzz, ran_fun=self.adbd.replay_ui_async, lifter=self.lifter)

        for function_to_fuzz in self.automated_senders:
            self.arg_fuzzer.start(function_to_fuzz, ran_fun=self.adbd.replay_ui_async, lifter=self.lifter)

        # Print the fuzz count for each function
        log.info("Fuzz count for each function:")
        log.info(self.fuzz_counter_arg_fuzzer.get_fuzz_count())

        log.info("Fuzzing done!")

    def run(self, phase=Phase.FUZZING):
        if phase >= Phase.RERAN:
            self.run_reran_phase()

        if not self.senders and phase >= Phase.MESSAGE_SENDER:
            self.run_message_sender_phase()

        if not self.sp and phase >= Phase.FUZZING_CANDIDATES:
            self.run_fuzzing_candidates_phase()

        if phase >= Phase.FUZZING:
            self.run_fuzzing_phase()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run.py <config_path> [phase]")
        sys.exit(1)

    config_path = sys.argv[1]

    try:
        with open(config_path) as fp:
            config = json.load(fp)
    except FileNotFoundError:
        print(f"Error: Config file '{config_path}' not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in config file '{config_path}'.")
        sys.exit(1)

    phase = Phase.FUZZING
    if len(sys.argv) > 2:
        phase = [value for name, value in vars(Phase).items() if name == sys.argv[2]]
        if not phase:
            print("Invalid phase, options are: " + str([x[6:] for x in list(map(str, Phase))]))
            sys.exit(0)
        phase = phase[0]

    IoTFuzzer(config).run(phase)
