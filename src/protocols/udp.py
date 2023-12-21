import struct

from .raw import RawPacket

class UdpPacket:
    def __init__(self, source_port=None, destination_port=None, length=None,
                 checksum=None, payload=None):
        self.src_port = source_port
        self.dst_port = destination_port
        self.length = length
        self.checksum = checksum
        self.higher_level_packet = payload
        self.name = 'UDP'

    def parse(self, packet):
        udp_header = struct.unpack('!HHHH', packet[:8])
        self.src_port = udp_header[0]
        self.dst_port = udp_header[1]
        self.length = udp_header[2]
        self.checksum = udp_header[3]
        self.higher_level_packet = RawPacket(packet[8:])

    def show(self, level):
        level_padding = '  ' * level
        print(f"{level_padding}Src Port: {self.src_port}, "
              f"Dst Port: {self.dst_port}, Length: {self.length}, "
              f"Checksum: {self.checksum}")
        if not self.higher_level_packet:
            return
        self.higher_level_packet.show(level + 1)