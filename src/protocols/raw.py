import dataclasses


@dataclasses.dataclass
class RawPacket:
    payload = None
    filter_name = 'row'

    def parse(self, packet):
        self.payload = packet

    def show(self, level):
        # Получаем шестнадцатеричное представление данных пакета
        hex_data = ''.join(f'{byte:02x}' for byte in self.payload)

        # Выводим данные пакета блоками по 4 байта, по 8 блоков в строке
        for i in range(0, len(hex_data), 32):
            offset = i // 2
            line = hex_data[i:i + 32]
            formatted_line = ' '.join(
                [line[j:j + 4] for j in range(0, len(line), 4)])
            ascii_repr = ''
            for j in range(0, len(line), 2):
                hex_byte = line[j:j + 2]
                ascii_char = chr(int(hex_byte, 16))
                if 32 <= ord(ascii_char) <= 126:
                    ascii_repr += ascii_char
                else:
                    ascii_repr += '.'
            padding = ' ' * (40 - len(formatted_line))
            level_padding = '  ' * level
            print(
                f"{level_padding}0x{offset:04x}:  "
                f"{formatted_line} {padding}{ascii_repr}")
