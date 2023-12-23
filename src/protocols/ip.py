import dataclasses
import socket
import struct
from datetime import datetime

from .raw import RawPacket
from .tcp import TcpPacket
from .udp import UdpPacket


ETH_TYPE_IP = 0x0008  # Тип пакета IP


class BaseIPPacket:
    version = None
    src_ip = None
    dst_ip = None
    higher_level_packet = None
    filter_name = 'ip'

    def check_higher_level_protocol(self, packet_data, protocol):
        if protocol == socket.IPPROTO_TCP:
            tcp_packet = TcpPacket()
            tcp_packet.parse(packet_data)
            self.higher_level_packet = tcp_packet
        elif protocol == socket.IPPROTO_UDP:
            udp_packet = UdpPacket()
            udp_packet.parse(packet_data)
            self.higher_level_packet = udp_packet
        else:
            raw_packet = RawPacket()
            raw_packet.parse(packet_data)
            self.higher_level_packet = raw_packet

    def show(self, ts_sec, level, verbose):
        level_padding = '  ' * level

        date = datetime.fromtimestamp(ts_sec)
        date_str = date.strftime('%H:%M:%S')

        src_ip = self.src_ip
        dst_ip = self.dst_ip
        if not isinstance(self.higher_level_packet, RawPacket):
            src_ip += f'.{self.higher_level_packet.src_port}:'
            dst_ip += f'.{self.higher_level_packet.dst_port}:'

        show_string = (f"{level_padding}{date_str} "
                       f"IPv{self.version} {src_ip} > {dst_ip} ")

        if not isinstance(self.higher_level_packet, RawPacket):
            show_string += (f"{self.higher_level_packet.name}, "
                            f"length {self.higher_level_packet.length}")
        print(show_string)
        if verbose:
            self.higher_level_packet.show(level + 1)


@dataclasses.dataclass
class IpPacket(BaseIPPacket):
    ihl = None
    ttl = None
    protocol = None
    name = 'IP'

    def parse(self, packet):
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])

        version_ihl = ip_header[0]
        self.version = version_ihl >> 4
        self.ihl = (version_ihl & 0xF) * 4
        self.ttl = ip_header[5]
        self.protocol = ip_header[6]
        self.src_ip = socket.inet_ntoa(ip_header[8])
        self.dst_ip = socket.inet_ntoa(ip_header[9])

        self.check_higher_level_protocol(packet[self.ihl:], self.protocol)


@dataclasses.dataclass
class Ipv6Packet(BaseIPPacket):
    traffic_class = None
    flow_label = None
    payload_length = None
    next_header = None
    hop_limit = None

    def parse(self, packet_data):
        version_tc_flow = struct.unpack('!I', packet_data[:4])[0]
        self.version = (version_tc_flow >> 28) & 0x0F
        self.traffic_class = (version_tc_flow >> 20) & 0xFF
        self.flow_label = version_tc_flow & 0xFFFFF

        self.payload_length, self.next_header, self.hop_limit = struct.unpack(
            '!HxB', packet_data[4:8])
        self.src_ip = socket.inet_ntop(socket.AF_INET6, packet_data[8:24])
        self.dst_ip = socket.inet_ntop(socket.AF_INET6, packet_data[24:40])
        self.check_higher_level_protocol(packet_data[40:], self.next_header)
