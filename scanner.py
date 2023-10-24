#!/usr/bin/env python3
from typing import Dict, List


class PortScannerException(Exception):
    pass


class ScanTask(object):
    def __init__(self):
        pass

    def set_tcp_scan(self):
        pass

    def set_udp_scan(self):
        pass

    def set_syn_scan(self):
        pass

    def set_icmp_probe(self):
        pass

    def set_ports_from_string(self, ports: str):
        pass

    def set_targets(self, targets: List[str]):
        pass

    def set_debug(self):
        pass

    def tcp_connect_port_scan(self) -> Dict[int, int]:
        pass

    def tcp_syn_port_scan(self) -> Dict[int, int]:
        pass

    def udp_port_scan(self) -> Dict[int, int]:
        pass

    def icmp_probe(self) -> bool:
        pass


def show_usage():
    pass


def show_help():
    pass


def show_version():
    pass


if __name__ == '__main__':
    import getopt
    import sys

    program = sys.argv[0]
    opts, args = getopt.getopt(sys.argv[1:], 'dvhtsuip:t:',
                               ['debug', 'version', 'help', 'tcp-scan', 'syn-scan', 'udp-scan', 'icmp-probe', 'ports=',
                                'timeout='])
    print(opts)
    print(args)
    if len(args) == 0:
        show_usage()
        exit(0)

    for opt,value in opts:
        print(opt, "=", value)
