import sys

from protocols.ethernet import EthernetPacket


class Filter:
    @staticmethod
    def filter(packet: EthernetPacket, filter_expr: str):
        pair = filter_expr.split('==', 1)
        key = pair[0].strip()
        packet_pair = key.split('.', 1)
        packet_name = packet_pair[0]

        if (len(pair) == 2 and len(packet_pair) == 1
                or len(pair) == 1 and len(packet_pair) == 2):
            print("Wrong filter")
            sys.exit(1)

        value = pair[1].strip() if len(pair) > 1 else None
        packet_field = packet_pair[1] if len(packet_pair) > 1 else None

        while packet.filter_name != packet_name:
            packet = packet.higher_level_packet

            if not packet or packet.filter_name == 'raw':
                return False

        if packet_field and str(getattr(packet, packet_field, None)) != value:
            return False

        return True

    @staticmethod
    def list_filter(class_type):
        print(f"{class_type.__name__} filters:")
        for key in class_type.__dict__.keys():
            if (not key.startswith("__") and key != "filter_name"
                    and key != "name" and key != "higher_level_packet"):
                print(f"    -{class_type.filter_name}.{key}")
