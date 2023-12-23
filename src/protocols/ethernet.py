import dataclasses
import struct
import socket

from .ip import IpPacket, ETH_TYPE_IP
from .raw import RawPacket


@dataclasses.dataclass
class EthernetPacket:
    src_mac = None
    dst_mac = None
    eth_type = None
    higher_level_packet = None
    name = 'Ethernet'
    filter_name = 'eth'

    def parse(self, packet):
        eth_header = struct.unpack('!6s6sH', packet[:14])
        self.src_mac = format_mac_addr(eth_header[0])
        self.dst_mac = format_mac_addr(eth_header[1])
        self.eth_type = socket.ntohs(eth_header[2])

        if self.eth_type == ETH_TYPE_IP:
            ip_packet = IpPacket()
            ip_packet.parse(packet[14:])
            self.higher_level_packet = ip_packet
        else:
            raw_packet = RawPacket()
            raw_packet.parse(packet[14:])

    def show(self, ts_sec, verbose):
        if not self.higher_level_packet:
            return
        self.higher_level_packet.show(ts_sec, 0, verbose)


def format_mac_addr(mac_addr):
    # Форматируем MAC-адрес в виде AA:BB:CC:DD:EE:FF
    formatted_mac = ':'.join('{:02x}'.format(byte) for byte in mac_addr)
    return formatted_mac
