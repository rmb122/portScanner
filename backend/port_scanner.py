import asyncio
import random
import struct
import socket
from enum import Enum
import typing
import re
import os
from constant import TOP_1000_PORTS, PORT_NAME_MAP
from argparse import ArgumentParser

event_loop = asyncio.get_event_loop()


def get_host_local_ip(target_addr) -> str:
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sck.connect((target_addr, 80))
        ip = sck.getsockname()[0]
    finally:
        sck.close()
    return ip


def get_raw_socket(protocol) -> socket.socket:
    sck = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
    sck.setblocking(False)
    return sck


def ip2bytes(ip: str):
    ret = bytearray()
    ip = ip.split(".")
    assert len(ip) == 4
    for i in ip:
        ret.append(int(i))
    return bytes(ret)


def bytes2ip(_bytes: bytes):
    ret = ''
    assert len(_bytes) == 4
    for i in _bytes:
        ret += str(i)
        ret += '.'
    return ret[:-1]


def set_event_loop(loop):
    global event_loop
    event_loop = loop


class TCPFlag:
    flag_ns: bool
    flag_cwd: bool
    flag_ece: bool
    flag_urg: bool
    flag_ack: bool
    flag_psh: bool
    flag_rst: bool
    flag_syn: bool
    flag_fin: bool

    __attr = ['flag_ns', 'flag_cwd', 'flag_ece', 'flag_urg', 'flag_ack', 'flag_psh', 'flag_rst', 'flag_syn', 'flag_fin']

    def __init__(self):
        for i in self.__attr:
            setattr(self, i, False)

    def to_int(self):
        ret = 0
        for i in self.__attr:
            i = getattr(self, i)
            ret <<= 1
            if i:
                ret ^= 1
        return ret

    def from_int(self, num):
        for i in self.__attr[::-1]:
            if num & 1 == 1:
                setattr(self, i, True)
            num >>= 1


class TCP:
    __src_addr: str
    __tgt_addr: str
    __src_port: int
    __tgt_port: int
    __syn_seq: int
    __ack_seq: int
    __window_size: int
    __packet: bytearray

    def __init__(self, src_addr, tgt_addr, src_port, tgt_port):
        self.__src_addr = src_addr
        self.__tgt_addr = tgt_addr
        self.__src_port = src_port
        self.__tgt_port = tgt_port

        self.__syn_seq = random.randint(0, 0xffffffff)
        self.__ack_seq = 0
        self.__window_size = 0xffff

    def __make_tcp_option(self):
        option = bytearray()
        option += b'\x02\x04\x05\xb4'  # TCP Option - Maximum segment size
        option += b'\x04\x02'  # TCP Option - SACK permitted
        option += b'\x08\x0a' + struct.pack("!I", random.randint(1000000000, 2000000000)) + struct.pack("!I", 0)  # TCP Option - Timestamps
        option += b'\x01'  # TCP Option - No-Operation (NOP)
        option += b'\x03\x03\x07'  # TCP Option - Window scale
        return option

    def __make_packet(self, tcp_flag: TCPFlag):
        self.__packet = bytearray()
        self.__packet += struct.pack("!H", self.__src_port)
        self.__packet += struct.pack("!H", self.__tgt_port)
        self.__packet += struct.pack("!I", self.__syn_seq)
        self.__packet += struct.pack("!I", self.__ack_seq)

        tcp_option = self.__make_tcp_option()
        assert len(tcp_option) % 4 == 0  # TCP 首部长度必须是 4 的倍数

        data_shift = 20 // 4 + len(tcp_option) // 4
        assert data_shift <= 0b1111

        self.__packet += struct.pack("!H", (data_shift << 12) + tcp_flag.to_int())
        self.__packet += struct.pack("!H", self.__window_size)
        self.__packet += struct.pack("!H", 0)  # 效验和, 用 0 占位
        self.__packet += struct.pack("!H", 0)  # 紧急指针, 不用, 设为 0 即可
        self.__packet += tcp_option

    def __arm_checksum(self):
        pseudo_header = bytearray()
        pseudo_header += ip2bytes(self.__src_addr)
        pseudo_header += ip2bytes(self.__tgt_addr)
        pseudo_header += b'\x00'
        pseudo_header += bytearray([socket.IPPROTO_TCP])
        pseudo_header += struct.pack("!H", len(self.__packet))
        pseudo_header += self.__packet

        check_sum = 0
        for i in range(0, len(pseudo_header), 2):
            check_sum += ((pseudo_header[i] << 8) + pseudo_header[i + 1])
            check_sum = (check_sum >> 16) + (check_sum & 0xffff)

        check_sum = ~check_sum & 0xffff
        check_sum = struct.pack("!H", check_sum)
        self.__packet[16] = check_sum[0]
        self.__packet[17] = check_sum[1]

    def get_syn_packet(self):
        tcp_flag = TCPFlag()
        tcp_flag.flag_syn = True

        self.__make_packet(tcp_flag)
        self.__arm_checksum()
        return bytes(self.__packet)

    def get_custom(self, tcp_flag: TCPFlag):
        self.__make_packet(tcp_flag)
        self.__arm_checksum()
        return bytes(self.__packet)


class PortStatus(Enum):
    STATUS_OPEN = "OPEN"
    STATUS_CLOSE = "CLOSE"
    STATUS_FILTERED = "FILTERED"
    STATUS_ILL_FORMAT = "ILL_FORMAT"


class OSType(Enum):
    Linux = 'Linux'
    Windows = 'Windows'
    Unknown = 'Unknown'


class ScanStatus(Enum):
    Waiting = "Waiting"
    Scanning = "Scanning"
    Done = "Done"


class TCPResolver:
    __src_addr: bytes
    __tgt_addr: bytes
    __src_port: int
    __tgt_port: int
    __tcp_flag: TCPFlag
    __is_tcp: bool

    def __init__(self, content):
        ip_info, _, ip_total_len, _, _, _, payload_type, _, self.__src_addr, self.__tgt_addr = struct.unpack("!BBHHHBBH4s4s", content[:20])
        ip_hdr_len = (ip_info & 0b1111) * 4
        ip_ver = (ip_info & 0b11110000) >> 4

        if ip_ver == 4 and payload_type == 6:  # ipv4 && tcp
            self.__is_tcp = True
            tcp_content = content[ip_hdr_len:]

            self.__src_port, self.__tgt_port, _, _, tcp_info = struct.unpack("!HHIIH", tcp_content[:14])
            self.__tcp_flag = TCPFlag()
            self.__tcp_flag.from_int(tcp_info)
        else:
            self.__is_tcp = False

    def get_tcp_flag(self):
        return self.__tcp_flag

    def get_src_port(self):
        return self.__src_port

    def get_src_addr(self):
        return self.__src_addr

    def get_tgt_port(self):
        return self.__tgt_port

    def is_match(self, src_addr: bytes, tgt_addr: bytes, tgt_port: int):
        if (self.__src_addr == src_addr or src_addr is None) and \
                (self.__tgt_addr == tgt_addr or tgt_addr is None) and \
                (self.__tgt_port == tgt_port or tgt_port is None) and self.__is_tcp:
            return True
        else:
            return False


class Ping:
    __packet: bytearray

    def __init__(self, identifier, payload=b'\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00'):
        self.__packet = bytearray()
        self.__packet += struct.pack("!BB", 8, 0)  # ICMP Type & code
        self.__packet += struct.pack("!HH", 0, identifier)  # checksum & Identifier
        self.__packet += struct.pack("!H", 1)  # seq num
        self.__packet += payload  # payload

        check_sum = 0
        for i in range(0, len(self.__packet), 2):
            check_sum += ((self.__packet[i] << 8) + self.__packet[i + 1])
            check_sum = (check_sum >> 16) + (check_sum & 0xffff)

        check_sum = ~check_sum & 0xffff
        check_sum = struct.pack("!H", check_sum)

        self.__packet[2] = check_sum[0]
        self.__packet[3] = check_sum[1]

    def get_packet(self):
        return self.__packet


class PingResolver:
    __is_icmp: bool
    __type: int
    __code: int
    __identifier: int
    __seq_num: int
    __src_addr: bytes

    def __init__(self, content):
        ip_info, _, ip_total_len, _, _, _, payload_type, _, self.__src_addr, _ = struct.unpack("!BBHHHBBH4s4s", content[:20])
        ip_hdr_len = (ip_info & 0b1111) * 4
        ip_ver = (ip_info & 0b11110000) >> 4

        if ip_ver == 4 and payload_type == 1:  # ipv4 && icmp
            self.__is_icmp = True
            icmp_content = content[ip_hdr_len:]

            self.__type, self.__code, _, self.__identifier, self.__seq_num = struct.unpack("!BBHHH", icmp_content[:8])
        else:
            self.__is_icmp = False

    def get_src_addr(self):
        return self.__src_addr

    def is_match(self, identifier: int):
        if self.__is_icmp and self.__identifier == identifier and self.__type == 0 and self.__code == 0:
            return True
        else:
            return False


class Host:
    ip_addr: str
    hostname: str
    is_online: bool
    port_status: typing.List[typing.Tuple[int, PortStatus]]
    os_type: OSType


async def send_tcp_to_self(avoid_port: int):
    sck = get_raw_socket(socket.IPPROTO_TCP)
    local_addr = "127.0.0.1"
    local_port = 50000
    while local_port == avoid_port:
        local_port = random.randint(50000, 65535)

    tcp = TCP(local_addr, local_addr, local_port, local_port)
    packet = tcp.get_syn_packet()

    sck.sendto(packet, (local_addr, 0))


async def send_icmp_to_self(avoid_identifier: int):
    sck = get_raw_socket(socket.IPPROTO_ICMP)
    local_addr = "127.0.0.1"
    identifier = 23333
    while identifier == avoid_identifier:
        identifier = random.randint(0, 0xffff)

    packet = Ping(identifier)
    packet = packet.get_packet()
    sck.sendto(packet, (local_addr, 0))


async def tcp_packet_sender(tgt_addr: str, tgt_ports: list, local_port: int, rate_limit=1000):
    sck = get_raw_socket(socket.IPPROTO_TCP)
    local_addr = get_host_local_ip(tgt_addr)

    for tgt_port in tgt_ports:
        tcp = TCP(local_addr, tgt_addr, local_port, tgt_port)
        packet = tcp.get_syn_packet()

        sck.sendto(packet, (tgt_addr, 0))
        await asyncio.sleep(1 / rate_limit)


async def tcp_packet_listener(tgt_addr: str, local_port: int, stop_signal: list) -> dict:
    sck = get_raw_socket(socket.IPPROTO_TCP)
    local_addr = get_host_local_ip(tgt_addr)
    local_addr = ip2bytes(local_addr)
    tgt_addr = ip2bytes(tgt_addr)
    port_map = {}

    while not stop_signal[0]:
        packet = await event_loop.sock_recv(sck, 1024)
        resolver = TCPResolver(packet)
        if resolver.is_match(tgt_addr, local_addr, local_port):
            tcp_flag = resolver.get_tcp_flag()
            src_port = resolver.get_src_port()

            if tcp_flag.flag_ack and tcp_flag.flag_rst:
                port_map[src_port] = PortStatus.STATUS_CLOSE
            elif tcp_flag.flag_ack and tcp_flag.flag_syn:
                port_map[src_port] = PortStatus.STATUS_OPEN
            else:
                port_map[src_port] = PortStatus.STATUS_ILL_FORMAT
    return port_map


async def icmp_packet_sender(tgt_addrs: list, identifier: int, rate_limit=100):
    sck = get_raw_socket(socket.IPPROTO_ICMP)
    packet = Ping(identifier)
    packet = packet.get_packet()
    for i in tgt_addrs:
        sck.sendto(packet, (i, 0))
        await asyncio.sleep(1 / rate_limit)


async def icmp_packet_listener(identifier: int, stop_signal: list) -> typing.List[str]:
    sck = get_raw_socket(socket.IPPROTO_ICMP)
    live_host = []

    while not stop_signal[0]:
        packet = await event_loop.sock_recv(sck, 1024)
        resolver = PingResolver(packet)
        if resolver.is_match(identifier):
            live_host.append(bytes2ip(resolver.get_src_addr()))
    return live_host


async def scan_host_port(tgt_addr: str, tgt_ports: list, wait_time=3, rate_limit=10000):
    local_port = random.randint(50000, 65535)
    random.shuffle(tgt_ports)

    stop_signal = [False]
    listener = asyncio.ensure_future(tcp_packet_listener(tgt_addr, local_port, stop_signal))
    sender = asyncio.ensure_future(tcp_packet_sender(tgt_addr, tgt_ports, local_port, rate_limit))

    await sender
    stop_signal[0] = True
    await asyncio.sleep(wait_time)
    await send_tcp_to_self(local_port)
    port_map = await listener

    result = [(i, port_map.get(i, PortStatus.STATUS_FILTERED)) for i in tgt_ports]
    result.sort(key=lambda x: x[0])  # 按端口大小排序
    return result


async def ping_hosts(hosts: typing.List[str], wait_time=3, rate_limit=100):
    identifier = random.randint(0, 0xffff)
    stop_signal = [False]

    listener = asyncio.ensure_future(icmp_packet_listener(identifier, stop_signal))
    sender = asyncio.ensure_future(icmp_packet_sender(hosts, identifier, rate_limit))

    await sender
    stop_signal[0] = True
    await asyncio.sleep(wait_time)
    await send_icmp_to_self(identifier)

    live_host = await listener

    return live_host


async def os_detect_packet_sender(tgt_addr_with_open_port: typing.Dict[str, int], local_port: int, rate_limit=300):
    tcp_flag = TCPFlag()  # All flag set to False. Linux won't send response, but Windows will send RST + ACK.
    sck = get_raw_socket(socket.IPPROTO_TCP)

    for _ in range(3):
        for addr, port in tgt_addr_with_open_port.items():
            local_addr = get_host_local_ip(addr)

            tcp = TCP(local_addr, addr, local_port, port)
            packet = tcp.get_custom(tcp_flag)
            sck.sendto(packet, (addr, 0))
            await asyncio.sleep(1 / rate_limit)


async def os_detect_listener(tgt_addr_with_open_port: typing.Dict[str, int], local_port: int, stop_signal: list) -> typing.Dict[str, OSType]:
    sck = get_raw_socket(socket.IPPROTO_TCP)
    result = {}

    while not stop_signal[0]:
        packet = await event_loop.sock_recv(sck, 1024)
        resolver = TCPResolver(packet)
        src_addr = bytes2ip(resolver.get_src_addr())
        if src_addr in tgt_addr_with_open_port and \
                tgt_addr_with_open_port[src_addr] == resolver.get_src_port() and \
                local_port == resolver.get_tgt_port():
            tcp_flag = resolver.get_tcp_flag()
            if tcp_flag.flag_rst and tcp_flag.flag_ack:
                result[src_addr] = OSType.Windows
            else:
                result[src_addr] = OSType.Unknown

    for i in tgt_addr_with_open_port:
        if i not in result:
            result[i] = OSType.Linux

    return result


async def detect_os_type(tgt_addr_with_open_port: typing.Dict[str, int], wait_time=3, rate_limit=300):
    local_port = random.randint(50000, 65535)
    stop_signal = [False]
    listener = asyncio.ensure_future(os_detect_listener(tgt_addr_with_open_port, local_port, stop_signal))
    sender = asyncio.ensure_future(os_detect_packet_sender(tgt_addr_with_open_port, local_port, rate_limit))

    await sender
    stop_signal[0] = True
    await asyncio.sleep(wait_time)
    await send_tcp_to_self(local_port)
    os_types = await listener

    return os_types


def split_ip(victims):
    """
    支持 1.1.1-100.1-100 和 1.1.1-233.1-2, 1.1.1.1 这种表达方式
    """
    result = set()
    if len(victims.split(',')) != 1:
        for i in victims.split(','):
            result = result.union(split_ip(i.strip()))
        return result

    parts = victims.split(".")
    assert len(parts) == 4
    for part in parts: # 以 . 分割成 4 部分
        tmp = set()
        if part.find('-') == -1: # 观察是否为 ip 段
            if len(result) != 0: # 是否是第一部分, 如果是第一部分, 直接加入到列表中
                for ip in result:
                    tmp.add(f"{ip}.{part}")
            else:
                tmp.add(part)
        else:
            if len(result) != 0:
                for ip in result:
                    f, b = part.split('-')[0], part.split('-')[1]
                    tmp = tmp.union([f"{ip}.{j}" for j in range(int(f), int(b) + 1)])
            else:
                f, b = part.split('-')[0], part.split('-')[1]
                tmp = tmp.union([str(j) for j in range(int(f), int(b) + 1)])
        result = tmp
    return result


def split_port(ports):
    result = set()

    if len(ports.split(',')) != 1:
        for i in ports.split(','):
            result = result.union(split_port(i.strip()))
        return result

    ports = ports.split("-")
    assert (len(ports) == 2) or (len(ports) == 1)
    if ports == 2:
        lower, upper = ports
        for i in range(int(lower), int(upper) + 1):
            result.add(i)
    else:
        result.add(int(ports[0]))
    return result


async def main():
    argparser = ArgumentParser()
    argparser.add_argument("-p", dest="ports", help="Ports that need to scan")
    argparser.add_argument("hosts", help="Target hosts that need scan")
    argparser.add_argument("--skip-ping", dest="skip_ping", help="Skip ping scan", action="store_true")
    argparser.add_argument("--only-ping", dest="only_ping", help="Only do ping scan", action="store_true")

    argparser.add_argument("--ping-timeout", dest="ping_timeout", help="The timeout that ping use", type=int, default=1)
    argparser.add_argument("--port-timeout", dest="port_timeout", help="The timeout that port scan use", type=int, default=1)
    argparser.add_argument("--os-timeout", dest="os_timeout", help="The timeout that os scan use", type=int, default=1)

    argparser.add_argument("--ping-rate", dest="ping_rate", help="The packet rate that ping use", type=int, default=100)
    argparser.add_argument("--port-rate", dest="port_rate", help="The packet rate that port scan use", type=int, default=1000)
    argparser.add_argument("--os-rate", dest="os_rate", help="The packet rate that os scan use", type=int, default=100)
    argparser.set_defaults(skip_ping=False, only_ping=False)
    result = argparser.parse_args()

    hosts_status = {}

    try:
        hosts = result.hosts
        if re.match(r'([0-9]{1,3}(-[0-9]{1,3})?\.){3}[0-9]{1,3}(-[0-9]{1,3})?', hosts):
            hosts = split_ip(hosts)
            for i in hosts:
                host = Host()
                host.hostname = None
                host.ip_addr = i
                host.is_online = False
                host.os_type = OSType.Unknown
                host.port_status = []
                hosts_status[i] = host
        else:
            host = Host()
            host.hostname = hosts
            hosts = [socket.gethostbyname(hosts)]

            host.ip_addr = hosts[0]
            host.is_online = False
            host.os_type = OSType.Unknown
            host.port_status = []
            hosts_status[hosts[0]] = host
    except Exception as e:
        print(f'Failed to resolve "{hosts}"')
        exit(-1)

    if os.getuid() != 0:
        print('You need root to run this program')
        exit(-1)

    if result.skip_ping and result.only_ping:
        print("You can't skip ping and only ping host!")
        exit(-1)

    if not result.skip_ping:
        print("Now check hosts is online by ping scan...")
        hosts = await ping_hosts(hosts, result.ping_timeout, result.ping_rate)
        print(f"Ping scan done, have {len(hosts)} hosts online, start port scan...\n")

    for i in hosts:
        hosts_status[i].is_online = True

    if not result.only_ping:
        ports = result.ports
        if ports is None:
            ports = TOP_1000_PORTS
        else:
            ports = split_port(ports)

        host_with_open_port = {}
        for host in hosts:
            print(f"Now scanning {host}...")
            port_result = await scan_host_port(host, ports, result.port_timeout, result.port_rate)
            hosts_status[host].port_status = port_result
            opened_port = [i[0] for i in port_result if i[1] == PortStatus.STATUS_OPEN]
            if len(opened_port) != 0:
                host_with_open_port[host] = opened_port[0]

        print(f"Now scanning os type for these hosts...")
        os_result = await detect_os_type(host_with_open_port, result.os_timeout, result.os_rate)
        for i in os_result:
            hosts_status[i].os_type = os_result[i]

    for k, v in hosts_status.items():
        host = hosts_status[k]
        if host.is_online:
            print(f"\nScan report for {k}")
            print("Host is online")

            have_open_port = False
            print(f"{('PORT').ljust(10, ' ')} STATE SERVICE")
            for port_num, status in host.port_status:
                if status == PortStatus.STATUS_OPEN:
                    have_open_port = True
                    print(f"{(str(port_num) + '/tcp').ljust(10, ' ')} OPEN  {PORT_NAME_MAP[port_num]}")

            print('')
            if have_open_port:
                print(f"Possible OS type: {host.os_type.value}")
            else:
                print("Can't detect OS type, need one open port")
        # else:
        #    print("Host is offline")


if __name__ == '__main__':
    event_loop.run_until_complete(main())
