import struct
import socket

from .ip import IpPacket, ETH_TYPE_IP


class EthernetPacket:
    def __init__(self, src_mac=None, dst_mac=None, eth_type=None,
                 higher_level_packet=None):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.eth_type = eth_type
        self.higher_level_packet = higher_level_packet
        self.name = 'Ethernet'

    def parse(self, packet):
        eth_header = struct.unpack('!6s6sH', packet[:14])
        self.src_mac = format_mac_addr(eth_header[0])
        self.dst_mac = format_mac_addr(eth_header[1])
        self.eth_type = socket.ntohs(eth_header[2])

        higher_level_data = packet[14:]
        if self.eth_type == ETH_TYPE_IP:
            ip_packet = IpPacket()
            ip_packet.parse(higher_level_data)
            self.higher_level_packet = ip_packet

    def show(self, ts_sec, ts_usec, verbose):
        if not self.higher_level_packet:
            return
        self.higher_level_packet.show(ts_sec, ts_usec, 0, verbose)



def format_mac_addr(mac_addr):
    # Форматируем MAC-адрес в виде AA:BB:CC:DD:EE:FF
    formatted_mac = ':'.join('{:02x}'.format(byte) for byte in mac_addr)
    return formatted_mac