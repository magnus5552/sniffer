import socket
import struct

from .tcp import TcpPacket
from .udp import UdpPacket


ETH_TYPE_IP = 0x0008  # Тип пакета IP


class IpPacket:
    def __init__(self, version=None, ihl=None, ttl=None, protocol=None,
                 src_ip=None, dst_ip=None, higher_level_protocol=None):
        self.version = version
        self.ihl = ihl
        self.ttl = ttl
        self.protocol = protocol
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.higher_level_packet = higher_level_protocol
        self.name = 'IP'

    def parse(self, packet):
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])

        version_ihl = ip_header[0]
        self.version = version_ihl >> 4
        self.ihl = (version_ihl & 0xF) * 4
        self.ttl = ip_header[5]
        self.protocol = ip_header[6]
        self.src_ip = socket.inet_ntoa(ip_header[8])
        self.dst_ip = socket.inet_ntoa(ip_header[9])


        self.check_higher_level_protocol(packet[self.ihl:])

    def check_higher_level_protocol(self, packet_data):
        if self.protocol == socket.IPPROTO_TCP:
            tcp_packet = TcpPacket()
            tcp_packet.parse(packet_data)
            self.higher_level_packet = tcp_packet
        elif self.protocol == socket.IPPROTO_UDP:
            udp_packet = UdpPacket()
            udp_packet.parse(packet_data)
            self.higher_level_packet = udp_packet

    def show(self, ts_sec, ts_usec, level, verbose):
        level_padding = '  ' * level
        print(f"{level_padding}{ts_sec}:{ts_usec} "
              f"IP {self.src_ip} > {self.dst_ip}: ", end='')
        if not self.higher_level_packet:
            return
        print(f"{self.higher_level_packet.name}, "
              f"length {self.higher_level_packet.length}")
        if verbose:
            self.higher_level_packet.show(level + 1)
