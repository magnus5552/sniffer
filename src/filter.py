import sys

from protocols.ethernet import EthernetPacket


class Filter:
    @staticmethod
    def filter(packet: EthernetPacket, filter_expr: str):
        pair = filter_expr.split('==', 1)
        if len(pair) == 1:
            print("Wrong filter")
            sys.exit(1)
        key, value = pair[0].strip(), pair[1].strip()
        packet_name, packet_field = key.split('.', 1)

        while packet.filter_name != packet_name:
            packet = packet.higher_level_packet

            if not packet or packet.filter_name == 'row':
                return False

        if str(getattr(packet, packet_field, None)) != value:
            return False

        return True

    @staticmethod
    def list_filter(class_type):
        print(f"{class_type.__name__} filters:")
        for key in class_type.__dict__.keys():
            if (not key.startswith("__") and key != "filter_name"
                    and key != "name" and key != "higher_level_packet"):
                print(f"    -{class_type.filter_name}.{key}")