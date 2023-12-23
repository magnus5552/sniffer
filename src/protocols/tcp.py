import dataclasses
import struct
from .raw import RawPacket


@dataclasses.dataclass
class TcpPacket:
    src_port = None
    dst_port = None
    seq_num = None
    ack_num = None
    data_offset = None
    flags = None
    window = None
    checksum = None
    urgent = None
    higher_level_packet = None
    name = 'TCP'
    length = None
    filter_name = 'tcp'

    def parse(self, packet):
        tcp_header = struct.unpack('!HHLLBBHHH', packet[:20])
        self.src_port = tcp_header[0]
        self.dst_port = tcp_header[1]
        self.seq_num = tcp_header[2]
        self.ack_num = tcp_header[3]
        self.data_offset = (tcp_header[4] >> 4) * 4
        self.flags = tcp_header[5]
        self.window = tcp_header[6]
        self.checksum = tcp_header[7]
        self.urgent = tcp_header[8]
        self.higher_level_packet = RawPacket()
        self.higher_level_packet.parse(packet[20:])
        self.length = len(packet[20:])

    def show(self, level):
        level_padding = '  ' * level
        print(
            f"{level_padding}{self.name}, Src Port: {self.src_port}, "
            f"Dst Port: {self.dst_port}, Seq: {self.seq_num}, "
            f"Ack: {self.ack_num}, Len: {self.length}")
        print(
            f"{level_padding}Data Offset: {self.data_offset}, "
            f"Flags: {self.flags}, Window: {self.window}, "
            f"Checksum: {self.checksum}, Urgent: {self.urgent}")
        if not self.higher_level_packet:
            return
        self.higher_level_packet.show(level + 1)