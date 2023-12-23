import os
import sys
import struct
import socket
import time

from cmd_parser import configure_parser
from protocols.ethernet import EthernetPacket
from protocols.ip import IpPacket, Ipv6Packet, BaseIPPacket
from protocols.tcp import TcpPacket
from protocols.udp import UdpPacket
from filter import Filter

ETH_P_ALL = 0x0003  # Захватывать все пакеты

classes = [EthernetPacket, IpPacket, Ipv6Packet, TcpPacket, UdpPacket]


def main():
    parser = configure_parser()
    args = parser.parse_args()
    if args.show_filter_list:
        for class_type in classes:
            Filter.list_filter(class_type)
        return
    sniff(args.interface, args.verbose, args.filter_expr)


def sniff(interface, verbose, filter_expr):
    # Создаем RAW сокет для захвата пакетов
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(ETH_P_ALL))

    # Открываем файл pcap для записи
    pcap_file = open('capture.pcap', 'wb')
    if interface != 'any':
        sock.bind((interface, 0))
    # Записываем файл заголовка pcap
    write_pcap_file_header(pcap_file)

    try:
        while True:
            # Захватываем пакеты
            packet, _ = sock.recvfrom(65535)

            timestamp = time.time()
            ts_sec = int(timestamp)
            ts_usec = int((timestamp - ts_sec) * 1000000)

            eth_packet = EthernetPacket()
            eth_packet.parse(packet)
            if filter_expr:
                if not evaluate_filter(eth_packet, filter_expr):
                    continue
            eth_packet.show(ts_sec, verbose)

            # Записываем пакет в pcap файл
            write_packet_to_pcap(pcap_file, packet, ts_sec, ts_usec)

    except KeyboardInterrupt:
        # Закрываем файл при остановке программы
        pcap_file.close()
        print("Capture stopped.")
        sys.exit(0)


def evaluate_filter(eth_packet, filter_expr):

    # Разбиваем выражение фильтрации на части
    parts = filter_expr.split()

    # Применяем условия фильтрации на внутренний пакет Ethernet
    for part in parts:
        if not Filter.filter(eth_packet, part):
            return False

    return True


def write_pcap_file_header(pcap_file):
    # Заголовок файла pcap
    pcap_file.write(struct.pack('IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))


def write_packet_to_pcap(pcap_file, packet, ts_sec, ts_usec):
    # Записываем заголовок пакета в pcap файл
    pcap_file.write(
        struct.pack('IIII', ts_sec, ts_usec, len(packet), len(packet)))
    pcap_file.write(packet)


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("This script requires root privileges to capture network traffic.")
        sys.exit(1)
    main()
