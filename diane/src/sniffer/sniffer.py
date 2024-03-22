import os
import time
import signal
import subprocess as sp
import logging
import re
import inspect
from multiprocessing import Process

logging.basicConfig()
log = logging.getLogger("Sniffer")
log.setLevel(logging.DEBUG)


class StopCapturing(Exception):
    pass


class Sniffer:
    def __init__(self, config, sniff_script="./sniff.sh", all_traffic_pcap_script="./dump_to_pcap.sh",
                 fifo_pipe="/tmp/sniff_data", sniffing_time_sec=60 * 30, keepalive_timeout_sec=60 * 1,
                 keepalive_threshold=0.5):
        self.android_ip = config['android_ip']
        self.device_ip = config['device_ip']
        self.ip_hotspot = config['ip_hot_spot']
        self.pass_ap = config['pass_ap']
        self.keep_alive_filters = []
        self.timer = None
        self.sniffing = False
        self.pids = []

        self.sniff_script = sniff_script
        self.all_traffic_pcap_script = all_traffic_pcap_script
        self.fifo_pipe = fifo_pipe
        self.sniffing_time_sec = sniffing_time_sec
        self.keepalive_timeout_sec = keepalive_timeout_sec
        self.keepalive_threshold = keepalive_threshold

        self.sync_sniffing = False
        signal.signal(signal.SIGUSR2, self.terminate)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, value, traceback):
        self.clean()
        if exception_type == StopCapturing:
            return True
            
    def execute_killall(self, process_name):
        cmd = f"killall -s 9 {process_name}"
        while True:
            p = sp.Popen(cmd, stdin=sp.PIPE, stderr=sp.PIPE, shell=True)
            _, e = p.communicate()
            if e:
                break

     def clean(self):
        # Some cleaning
        if self.timer is not None and self.timer.is_alive():
            self.timer.terminate()

        # kill local process
        self.execute_killall("sniff.sh")

        # kill remote tcpdump
        if not self.pids:
            log.debug("Killing all tcpdump processes")
            cmd = f'sshpass -p {self.pass_ap} ssh root@{self.ip_hotspot} "killall tcpdump"'
            p = sp.Popen(cmd, stdin=sp.PIPE, stderr=sp.PIPE, shell=True)
            p.communicate()
        else:
            for p in self.pids:
                log.debug(f"Killing tcpdump pid: {p}")
                cmd = f'sshpass -p {self.pass_ap} ssh root@{self.ip_hotspot} "kill -9 {p}"'
                while True:
                    p = sp.Popen(cmd, stdin=sp.PIPE, stderr=sp.PIPE, shell=True)
                    _, e = p.communicate()
                    if e:
                        break


    def timeout(self, sec):
        time.sleep(sec)
        os.kill(os.getppid(), signal.SIGUSR2)

    def detect_keepalive(self):
        try:
            sizes = {}
            for p in self.sniff_packets(sniffing_time=self.keepalive_timeout_sec):
                regex = re.compile(".*length ([0-9]*):")
                match = regex.match(p)
                if match:
                    eth_len = int(match.group(1))
                    if eth_len not in sizes:
                        sizes[eth_len] = 0
                    sizes[eth_len] += 1
                    log.info(f"Packet of length {eth_len} sniffed")

            tot_bytes = sum([x for x in sizes.values()])
            for eth_len, count in sizes.items():
                if count / float(tot_bytes) < self.keepalive_threshold:
                    continue
                filter_ = f"'(greater {eth_len + 1} or less {eth_len - 1})'"
                if filter_ not in self.keep_alive_filters:
                    self.keep_alive_filters.append(filter_)
        except Exception as e:
            log.error(f"Error detecting keepalive: {str(e)}")
            self.clean()
            raise
    def apply_keepalive_filters(self):
        if not self.keep_alive_filters:
            return ''
        return ' and ' + ' and '.join(self.keep_alive_filters)

    def create_pipe(self):
        if os.path.exists(FIFO_PIPE):
            os.remove(FIFO_PIPE)
            time.sleep(1)
        os.mkfifo(FIFO_PIPE)

    def find_pids(self, old_pids):
        pids = self.get_opened_tcpdumps()
        self.pids = [p for p in pids if p not in old_pids]

    def get_opened_tcpdumps(self):
        cmd = "sshpass -p {} ssh root@{} \"ps | grep tcpdump\"".format(self.pass_ap, self.ip_hotspot)
        p = sp.Popen(cmd, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, shell=True)
        o, e = p.communicate()
        dumps = [x for x in o.split('\n') if 'grep' not in x and x]
        pids = [[y for y in x.split(' ') if y][0] for x in dumps]
        return pids

    def start_capturing_traffic(self):
        self.create_pipe()
        path_script = os.path.dirname(__file__) + '/' + SNIFF_SCRIPT
        cmd = "{} {} {} {} {} {}&".format(path_script, self.pass_ap, self.ip_hotspot,
                                          self.android_ip, self.device_ip, self.apply_keepalive_filters())
        pids = self.get_opened_tcpdumps()
        os.system(cmd)
        time.sleep(1)
        self.find_pids(pids)

    def sniff_packets(self, sniffing_time=SNIFFING_TIME_SEC, n_packets=None):
        global SYNC_SNIFFING
        log.info("Sniffing packets, press CTRL+C to stop (max sniffing time: {} mins)".format(
            str(sniffing_time / 60)))

        self.start_capturing_traffic()
        fifo = open(FIFO_PIPE)
        counter = 0
        SYNC_SNIFFING = True
        self.timer = Process(target=self.timeout, args=(sniffing_time,))
        self.timer.start()
        while True:
            if n_packets and counter == n_packets:
                log.info("Sniffed {} packets".format(str(n_packets)))
                self.terminate()
            line = fifo.readline()
            counter += 1
            yield line

    def dump_all_traffic_to_pcap(self, pcap_path):
        path_script = os.path.dirname(__file__) + '/' + ALL_TRAFFIC_PCAP_SCRIPT
        cmd = "{} {} {} {}&".format(path_script, self.pass_ap, self.ip_hotspot, pcap_path)
        pids = self.get_opened_tcpdumps()
        os.system(cmd)
        time.sleep(1)
        self.find_pids(pids)

    def terminate(self, *args, **kwargs):
        global SYNC_SNIFFING
        sniffing = False
        if len(args) == 2 and args[0] == signal.SIGUSR2:
            sniffing = args[1].f_globals['SYNC_SNIFFING']
            args[1].f_globals['SYNC_SNIFFING'] = False

        if sniffing or SYNC_SNIFFING:
            SYNC_SNIFFING = False
            raise StopCapturing

        self.clean()


if __name__ == "__main__":
    import json

    config_path = '../experiments/wans/config_wans.json'
    with open(config_path) as fp:
        config = json.load(fp)

    print "Dumping pcap to /tmp/test_capture.pcap"
    with Sniffer(config) as sniffer:
        sniffer.dump_all_traffic_to_pcap('/tmp/test_capture.pcap')
        time.sleep(5)
        sniffer.terminate()

    print "Sniffing for 5 seconds"
    with sniffer as sn:
        for p in sn.sniff_packets(5):
            print p

    print "Sniffing two packets"
    with sniffer as sn:
        for p in sn.sniff_packets(n_packets=2):
            print p
    print "DONE"
