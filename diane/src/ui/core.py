import subprocess
import signal
import os
import os.path
import json


from .config import *


class UITimeoutError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class ADBDriver:
    def __init__(self, f_path=None, device_id=None):
        self.device_id = device_id
        self.c_opt = True
        self.f_path = f_path
        self.set_su_shell()
        self._translate_events_log(f_path)
        self.adb_cmd(['push', REPLAY_PATH, '/sdcard/replay'])
        self.adb_su_cmd('cp /sdcard/replay ' + REPLAY_REMOTE_PATH)
        self.adb_su_cmd('chmod 755 ' + REPLAY_REMOTE_PATH)

    def set_su_shell(self):
        o, e = self.adb_su_cmd('ls')
        o += e
        if 'invalid' in o and '-c' in o:
            self.c_opt = False

    def _fix_log(self, f_path):
        f = open(f_path)
        content = f.read()
        f.close()

        new = content.replace(']', '')
        new = new.replace('.', '-')

        new_array = new.splitlines()

        for i in range(len(new_array)):
            if new_array[i].startswith(' '):
                new_array[i] = new_array[i][1:]
            if new_array[i].startswith('['):
                new_array[i] = new_array[i][1:].lstrip()

        if len(new_array[-1].split(' ')) != 5:
            new_array = new_array[:-1]

        new = '\n'.join(new_array)
        f = open(f_path, 'w')
        f.write(new)
        f.close()

    def _translate_events_log(self, f_path):
        if f_path is not None:
            t_path = os.path.join(os.path.dirname(f_path), 'translatedEvents.txt')
            cmd = ['java', '-jar', TRANSLATOR_PATH, f_path, t_path]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
            if 'Total number of events written' not in out:
                raise Exception('Translator failed.out:{0}.err:{1}'.format(out, err))

            self.adb_cmd(['push', t_path, '/sdcard/translatedEvents.txt'])

    def build_adb_cmd(self, args, device_id=None, su=False):
        cmd = [ADB_PATH]
        if device_id is not None:
            cmd += ['-s', device_id]
        if su:
            if self.c_opt:
                cmd += ['shell', 'su', '-c']
            else:
                cmd += ['shell', 'su', '0']
        cmd.extend(args)
        return cmd

    def adb_cmd(self, args, cmd_wait_time=CMD_WAIT_TIME):
        cmd = self.build_adb_cmd(args, device_id=self.device_id)
        print('Executing ' + ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        return out, err

    def adb_su_cmd(self, args, cmd_wait_time=CMD_WAIT_TIME):
        cmd = self.build_adb_cmd(args, device_id=self.device_id, su=True)
        print('Executing ' + ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        signalset = False
        if signal.getsignal(signal.SIGALRM) == signal.SIG_DFL:
            signal.signal(signal.SIGALRM, self.adb_sighandler)
            signal.alarm(cmd_wait_time)
            signalset = True

        try:
            out, err = p.communicate()
            if signalset:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, signal.SIG_DFL)

        except UITimeoutError:
            p.terminate()
            raise UITimeoutError('Timeout executing adb command: ' + str(cmd))

        return out, err

    def adb_su_cmd_async(self, args, cmd_wait_time=CMD_WAIT_TIME, device_id=None):
        cmd = self.build_adb_cmd(args, device_id=device_id, su=True)
        print('Executing ' + ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
        return p

    def adb_sighandler(self, signum, frame):
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        raise UITimeoutError('Could not execute adb command: timeout')

    def record_ui(self, events_log_path):
        print('Starting RERAN recording')
        cmd = self.build_adb_cmd(['shell', 'getevent', '-tt'], device_id=self.device_id)
        cmd += ['> ', events_log_path]
        print('Executing ' + ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        key = ''
        while key != 'c':
            key = input('Stimulate app & press "c" to continue..\n')

        p.kill()

        self._fix_log(events_log_path)
        self._translate_events_log(events_log_path)

    def replay_ui(self):
        print('RERAN replaying')
        self.adb_su_cmd([REPLAY_REMOTE_PATH, '/sdcard/translatedEvents.txt'])

    def replay_ui_async(self):
        print('RERAN replaying (async)')
        return self.adb_su_cmd_async([REPLAY_REMOTE_PATH, '/sdcard/translatedEvents.txt'])

    def start_monkey(self, package=None, seed=None, throttle=THROTTLE,
                     pct_syskeys=PCT_SYSKEYS, pct_anyevent=PCT_ANYEVENT,
                     num_events=NUM_EVENTS, ignore_crashes=IGNORE_CRASHES,
                     ignore_timeouts=IGNORE_TIMEOUTS,
                     ignore_security_exceptions=IGNORE_SECURITY_EXCEPTIONS):
        print('Starting monkey')

        cmd = ['shell', 'monkey']

        if seed:
            cmd.extend(['-s', seed])

        if package:
            cmd.extend(['-p', package])

        cmd.extend(['--throttle', throttle,
                    '--pct-syskeys', pct_syskeys,
                    '--pct-anyevent', pct_anyevent,
                    str(num_events)])

        if ignore_crashes:
            cmd.append('--ignore-crashes')

        if ignore_timeouts:
            cmd.append('--ignore-timeouts')

        if ignore_security_exceptions:
            cmd.append('--ignore-security-exceptions')

        return self.adb_cmd(cmd, cmd_wait_time=MONKEY_TIMEOUT)

    def tap(self, x, y):
        return self.adb_cmd(['shell', 'input', 'tap', str(x), str(y)])

    def install_apk(self, apk_path):
        return self.adb_cmd(['install', '-r', apk_path])

    def uninstall_apk(self, package_name):
        return self.adb_cmd(['uninstall', package_name])

    def get_device_info(self):
        info = {}
        out, err = self.adb_cmd(['shell', 'getprop'])
        for line in out.decode('utf-8').split('\n'):
            if not line:
                continue
            key, value = line.split(':', 1)
            info[key.strip()] = value.strip()

        return info

if __name__ == '__main__':
    import json
    import time
    import sys

    try:
        config_path = sys.argv[1]
        mode = 0 if sys.argv[2] == 'record' else 1
    except:
        print("Usage: {} [config path] [record/replay]".format(sys.argv[0]))
        sys.exit(1)

    config = json.load(open(config_path))
    rec_path = config['reran_record_path']
    if mode == 0:
        rec_path = None
    adbd = ADBDriver(device_id=config['device_id'], f_path=rec_path)

    if mode == 0:
        adbd.record_ui('/tmp/reran.log')
        print("Ran stored in /tmp/reran.log")
    else:
        adbd.replay_ui()

    print("Done.")
