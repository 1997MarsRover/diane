import pyshark
import logging
import os
from os.path import dirname, abspath
import contextlib
import sys

sys.path.append(dirname(dirname(abspath(__file__))))

from ui.core import ADBDriver

logging.basicConfig()
log = logging.getLogger("BltLogAnalyzer")
log.setLevel(logging.DEBUG)

class BltLogAnalyzer:
    def __init__(self, adb_driver, local_logfile_path, remote_logfile_path):
        self._keep_alives = {}
        self.adb_driver = adb_driver
        self.local_logfile_path = local_logfile_path
        self.remote_logfile_path = remote_logfile_path

    @contextlib.contextmanager
    def _log_file(self):
        self.adb_driver.adb_su_cmd(f'cp {self.remote_logfile_path} /sdcard/my_blt_log')
        self.adb_driver.adb_cmd(['pull', '/sdcard/my_blt_log', self.local_logfile_path])
        try:
            yield self.local_logfile_path
        finally:
            if os.path.isfile(self.local_logfile_path):
                os.remove(self.local_logfile_path)

    def update_keep_alives(self, capture):
        for packet in capture:
            if hasattr(packet, 'hci_h4'):
                # direction is SENT
                if packet.hci_h4.direction == '0x00000000':
                    if packet.length not in self._keep_alives:
                        self._keep_alives[packet.length] = set()

                    if hasattr(packet, 'btatt') and hasattr(packet.btatt, 'value'):
                        self._keep_alives[packet.length].add(str(packet.btatt.value))

    def detect_keep_alives(self):
        log.info('Detecting BL keep-alives')
        with self._log_file() as log_file:
            capture = pyshark.FileCapture(log_file)
            self.update_keep_alives(capture)
            capture.close()
            if not capture.eventloop.is_closed():
                capture.eventloop.close()

    def _is_keep_alive(self, packet):
        if hasattr(packet, 'hci_h4'):
            if packet.hci_h4.direction == '0x00000000' and hasattr(packet, 'btatt'):
                if packet.length in self._keep_alives:
                    #if str(packet.btatt.value) in self._keep_alives[packet.length]:
                        return True
        return False

    def parse_packets(self, capture):
        for packet in capture:
            if hasattr(packet, 'hci_h4'):
                # direction is SENT
                if packet.hci_h4.direction == '0x00000000':
                    if not self._is_keep_alive(packet):
                        yield packet

    def get_new_sent_packet_ts(self, start_ts):
        with self._log_file() as log_file:
            capture = pyshark.FileCapture(log_file)
            timestamp = None
            for packet in self.parse_packets(capture):
                if float(packet.sniff_timestamp) > start_ts:
                    log.debug('New BL packet: {}'.format(packet.sniff_timestamp))
                    timestamp = float(packet.sniff_timestamp)
                    break

            capture.close()
            if not capture.eventloop.is_closed():
                capture.eventloop.close()

        if timestamp is None:
            log.debug('No new BL packet')
        return timestamp
