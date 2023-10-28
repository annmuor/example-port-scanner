#!/usr/bin/env python3
import random
import select
import socket
import struct
import time
from typing import List, Tuple


class PortScannerException(Exception):
    pass


class ScanTask(object):
    SCAN_TYPE_TCP = 0
    SCAN_TYPE_SYN = 1
    SCAN_TYPE_UDP = 2

    PORT_TYPE_OPEN = 0
    PORT_TYPE_CLOSED = 1
    PORT_TYPE_FW = 2

    def __init__(self):
        self.scan_type = ScanTask.SCAN_TYPE_TCP
        self.probe_icmp = False
        self.targets = []
        self.ports = []
        self.debug = False
        self.timeout = 1
        self.targets = []
        self.set_ports_from_string('1-1024')

    def set_udp_scan(self):
        self.scan_type = ScanTask.SCAN_TYPE_UDP

    def set_syn_scan(self):
        self.scan_type = ScanTask.SCAN_TYPE_SYN

    def set_icmp_probe(self):
        self.probe_icmp = True

    def set_ports_from_string(self, ports: str):
        result = []

        def try_str_to_port(maybe_port: str) -> int:
            try:
                maybe_port = int(maybe_port)
                assert 1 <= maybe_port <= 65535
                return maybe_port
            except ValueError:
                raise PortScannerException(f"{group} is not valid integer")
            except AssertionError:
                raise PortScannerException(f"{group} is not between 1 and 65535")

        for group in ports.split(","):
            if '-' in group:
                port_range = group.split('-')
                if len(port_range) != 2:
                    raise PortScannerException("{group} has invalid range")
                start_port = try_str_to_port(port_range[0])
                end_port = try_str_to_port(port_range[1])
                try:
                    assert end_port > start_port
                except AssertionError:
                    raise PortScannerException(f"{start_port} >= {end_port} in the range {group}")
                for port in range(start_port, end_port + 1):
                    result.append(port)
            else:
                result.append(try_str_to_port(group))
        self.ports = result

    def set_targets(self, targets: List[str]):
        try:
            self.targets = [socket.gethostbyname(x) for x in targets][:]
        except socket.gaierror:
            raise PortScannerException("target resolution failed")

    def set_timeout_from_string(self, timeout: str):
        pass

    def set_debug(self):
        self.debug = True

    def run(self):
        def find_def_status(def_ports: List[Tuple[int, int]]) -> int:
            v = [x for _, x in ports]
            na = {
                ScanTask.PORT_TYPE_CLOSED: v.count(ScanTask.PORT_TYPE_CLOSED),
                ScanTask.PORT_TYPE_FW: v.count(ScanTask.PORT_TYPE_FW),
            }
            return max(na, key=lambda x: na[x])

        def print_status(port_status: int) -> str:
            return "open" if port_status == ScanTask.PORT_TYPE_OPEN \
                else "closed" if port_status == ScanTask.PORT_TYPE_CLOSED \
                else "firewalled"

        result = dict()
        timer_start = time.time()
        for target in self.targets:
            if self.probe_icmp:
                if not self.icmp_probe(target):
                    print(f"[!] {target} is DOWN according to ICMP probe, skipping")
                    continue
                else:
                    print(f"[+] {target} is UP, ICMP probe succeeded")
            if self.scan_type == ScanTask.SCAN_TYPE_SYN:
                result[target] = self.tcp_syn_port_scan(target)
            elif self.scan_type == ScanTask.SCAN_TYPE_TCP:
                result[target] = self.tcp_connect_port_scan(target)
            elif self.scan_type == ScanTask.SCAN_TYPE_UDP:
                result[target] = self.udp_port_scan(target)
        elapsed = (time.time() - timer_start)
        print(f"[+] Scan done, it took {elapsed} seconds to complete the job")
        for target in result:
            print(f"\tResults for {target}")
            ports = result[target]
            def_state = find_def_status(ports)
            for port, status in [(x, y) for x, y in ports if y != def_state]:
                print(f"\t\t{port} is {print_status(status)}")
            print(f"\t[!!] all other ports is {print_status(def_state)}")

    def tcp_connect_port_scan(self, target: str) -> List[Tuple[int, int]]:
        result = []
        idx = 0
        while idx < len(self.ports):
            ports = self.ports[idx:idx + 500]
            idx += 500
            socs = []
            for port in ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                s.setblocking(False)
                try:
                    s.connect((target, port))
                except OSError as e:
                    if e.errno == 115:
                        socs.append(s)
                    else:
                        raise e
            while len(socs) > 0:
                r, w, x = select.select(socs, socs, socs, 1.0)
                ready = set(r) | set(w) | set(x)
                for s in ready:
                    try:
                        host, port = s.getpeername()
                        result.append((port, ScanTask.PORT_TYPE_OPEN))
                    except Exception as e:
                        pass
                    finally:
                        socs.remove(s)
                        s.close()
                if len(ready) == 0:
                    [x.close() for x in socs]
                    break

        return result

    def tcp_syn_port_scan(self, target: str) -> List[Tuple[int, int]]:

        def get_my_ip(target: str) -> Tuple[str, str]:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            test_sock.connect((target, 1))
            my_ip, _ = test_sock.getsockname()
            test_sock.close()
            return my_ip

        def pack_ip_header(src, dst):
            ip_ihl = 5
            ip_ver = 4
            ip_tos = 0
            ip_len = 0
            ip_id = 33
            ip_frag = 0
            ip_ttl = 64
            ip_proto = socket.IPPROTO_TCP
            ip_check = 0
            ip_saddr = socket.inet_aton(src)
            ip_daddr = socket.inet_aton(dst)
            ip_ihl_ver = (ip_ver << 4) + ip_ihl
            return struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check,
                               ip_saddr, ip_daddr)

        def unpack_ip_header(header) -> Tuple[str, str]:
            ip_ihl_ver, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, \
                ip_saddr, ip_daddr = struct.unpack('!BBHHHBBH4s4s', header)
            return socket.inet_ntoa(ip_saddr), socket.inet_ntoa(ip_daddr)

        def pack_tcp_header(sport, dport, check=0):
            tcp_seq = 0
            tcp_ack = 0
            tcp_doff = (5 << 4) + 0
            tcp_flags = 0 + (1 << 1) + (0 << 2) + (0 << 3) + (0 << 4) + (0 << 5)
            tcp_window = 0
            tcp_hdr = struct.pack('!HHLLBBHHH', sport, dport, tcp_seq, tcp_ack, tcp_doff, tcp_flags, tcp_window, check,
                                  0)
            return tcp_hdr

        def unpack_tcp_header(header) -> Tuple[int, int, int]:
            sport, dport, tcp_seq, tcp_ack, tcp_doff, \
                tcp_flags, tcp_window, check, urg = struct.unpack('!HHLLBBHHH', header)
            return (sport, dport, tcp_flags)

        def repack_tcp_header(src, dst, sport, dport):
            src_ip = socket.inet_aton(src)
            dst_ip = socket.inet_aton(dst)
            tcp_hdr = pack_tcp_header(sport, dport)
            hdr = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, socket.IPPROTO_TCP, len(tcp_hdr))
            hdr = hdr + tcp_hdr
            check = 0
            for i in range(0, len(hdr), 2):
                w = (hdr[i] << 8) + (hdr[i + 1])
                check = check + w
            check = (check >> 16) + (check & 0xffff)
            check = ~check & 0xffff
            return pack_tcp_header(sport, dport, check)

        my_ip = get_my_ip(target)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        sock.bind((my_ip, 0))
        queue = self.ports
        result = []
        # now let's setup queue
        count = 0
        now = time.time() - 2
        while len(queue) > 0 and count < 3:
            r, w, _ = select.select([sock], [], [], 1.0)
            if sock in r:
                buf, _ = sock.recvfrom(65565)
                src, dst = unpack_ip_header(buf[0:20])
                if dst == my_ip and src == target:
                    sport, dport, flags = unpack_tcp_header(buf[20:40])
                    if dport == 65533:  # we use this dport
                        if flags == 0x12:  # SYN+ACK
                            result.append((sport, ScanTask.PORT_TYPE_OPEN))
                        elif flags == 0x14 or flags == 0x04:  # RST+ASK or RST
                            result.append((sport, ScanTask.PORT_TYPE_CLOSED))
                        queue.remove(sport)
            if now + 2 <= time.time():
                now = time.time()

                for port in queue:
                    ip_hdr = pack_ip_header(my_ip, target)
                    tcp_hdr = repack_tcp_header(my_ip, target, 65533, port)
                    sock.sendto(ip_hdr + tcp_hdr, (target, 0))
                count += 1
        result.extend([(x, ScanTask.PORT_TYPE_FW) for x in queue])
        return result

    def udp_port_scan(self, target: str) -> List[Tuple[int, int]]:
        def random_status() -> int:
            return random.randint(0, 2)

        return [(x, random_status()) for x in self.ports]

    def icmp_probe(self, target: str) -> bool:
        # mock
        return True


if __name__ == '__main__':
    import getopt
    import sys

    program = sys.argv[0]


    def show_usage():
        print(f"Usage: {program} [-hvdtsui] [-p ports] [-t timeout] <target1> [.. targetN]")


    def show_unknown(x):
        print(f"Unknown option {x}. Run {program} --help for help")


    def show_help():
        show_version()
        show_usage()
        print("Options:")
        print("\t-h, --help - show this help and exit")
        print("\t-v, --version - show version and exit")
        print("\t-d, --debug - enable debug output")
        print("\t-s, --syn-scan - switch to SYN scan mode ( requires r00t )")
        print("\t-u, --udp-scan - switch to UDP scan mode")
        print("\t-i, --icmp-probe - Add ICMP probes before scanning ( requires r00t )")
        print("\t-p ports, --ports=ports - Ports to scan. Default: 1-1024")
        print("\t-t timeout, --timeout=timeout - timeout for port checking. Default - 1 second")


    def show_version():
        print("Example Port Scanner by NUP23 Computer Network Group v. 0.1")


    task = ScanTask()
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hvdsuip:t:',
                                   ['help', 'version', 'debug', 'syn-scan', 'udp-scan', 'icmp-probe',
                                    'ports=',
                                    'timeout='])
        for opt, value in opts:
            if opt == '-h' or opt == '--help':
                show_help()
                exit(0)
            elif opt == '-v' or opt == '--version':
                show_version()
                exit(0)
            elif opt == '-d' or opt == '--debug':
                task.set_debug()
            elif opt == '-s' or opt == '--syn-scan':
                task.set_syn_scan()
            elif opt == '-u' or opt == '--udp-scan':
                task.set_udp_scan()
            elif opt == '-i' or opt == '--icmp-probe':
                task.set_icmp_probe()
            elif opt == '-p' or opt == '--ports':
                task.set_ports_from_string(value)
            elif opt == '-t' or opt == '--timeout':
                task.set_timeout_from_string(value)
        if len(args) == 0:
            show_usage()
            exit(0)
        task.set_targets(args)
    except getopt.GetoptError as e:
        print(f"[!] Error: {e.msg}")
        show_help()
        exit(-1)
    except PortScannerException as e:
        print(f"[!] Error: {e}")
        show_help()
        exit(-1)
    task.run()
