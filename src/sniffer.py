import os
import sys
import struct
import socket
import time

ETH_P_ALL = 0x0003  # Захватывать все пакеты
ETH_TYPE_IP = 0x0800  # Тип пакета IP


def main():
    # Создаем RAW сокет для захвата пакетов
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(ETH_P_ALL))

    # Открываем файл pcap для записи
    pcap_file = open('capture.pcap', 'wb')

    # Записываем файл заголовка pcap
    write_pcap_file_header(pcap_file)

    try:
        while True:
            # Захватываем пакеты
            packet, _ = sock.recvfrom(65535)

            # Парсим заголовок Ethernet
            eth_header = struct.unpack('!6s6sH', packet[:14])
            source_mac = format_mac_addr(eth_header[0])
            dest_mac = format_mac_addr(eth_header[1])
            ether_type = socket.ntohs(eth_header[2])

            # Записываем пакет в pcap файл
            write_packet_to_pcap(pcap_file, packet)

            # Выводим информацию о пакете
            print(f"Source MAC: {source_mac}, Destination MAC: {dest_mac}")

    except KeyboardInterrupt:
        # Закрываем файл при остановке программы
        pcap_file.close()
        print("Capture stopped.")
        sys.exit(0)


def write_pcap_file_header(pcap_file):
    # Заголовок файла pcap
    pcap_file.write(struct.pack('IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))


def write_packet_to_pcap(pcap_file, packet):
    # Получаем время захвата пакета
    timestamp = time.time()
    seconds = int(timestamp)
    microseconds = int((timestamp - seconds) * 1000000)

    # Записываем заголовок пакета в pcap файл
    pcap_file.write(
        struct.pack('IIII', seconds, microseconds, len(packet), len(packet)))
    pcap_file.write(packet)


def format_mac_addr(mac_addr):
    # Форматируем MAC-адрес в виде AA:BB:CC:DD:EE:FF
    formatted_mac = ':'.join('{:02x}'.format(byte) for byte in mac_addr)
    return formatted_mac


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("This script requires root privileges to capture network traffic.")
        sys.exit(1)
    main()
