import dataclasses
import struct
from raw import RawPacket


@dataclasses.dataclass
class UdpPacket:
    src_port = None
    dst_port = None
    length = None
    checksum = None
    higher_level_packet = None
    name = 'UDP'
    filter_name = 'udp'

    def parse(self, packet):
        udp_header = struct.unpack('!HHHH', packet[:8])
        self.src_port = udp_header[0]
        self.dst_port = udp_header[1]
        self.length = udp_header[2]
        self.checksum = udp_header[3]
        self.higher_level_packet = RawPacket()
        self.higher_level_packet.parse(packet[8:])

    def show(self, level):
        level_padding = '  ' * level
        print(f"{level_padding}{self.name}, Src Port: {self.src_port}, "
              f"Dst Port: {self.dst_port}, Length: {self.length}, "
              f"Checksum: {self.checksum}")
        if not self.higher_level_packet:
            return
        self.higher_level_packet.show(level + 1)