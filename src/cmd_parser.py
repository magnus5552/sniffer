from argparse import ArgumentParser


def configure_parser():
    parser = ArgumentParser(description="tool to sniff traffic")
    parser.add_argument('-i', '--interface', dest='interface',
                        default='any',
                        help='network interface (default: any)')
    parser.add_argument('-f', '--file', dest='filename',
                        default='capture.pcap',
                        help='path to .pcap file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        dest='verbose',
                        help='verbose mode')
    parser.add_argument('--filter', dest='filter_expr',
                        help='filter expression in format <protocol> or'
                             '<protocol>.<header>==<value>, see sniffer.py '
                             '-l to list available filters')
    parser.add_argument('-l', '--filter-list', action='store_true',
                        dest='show_filter_list',
                        help='available protocols and headers to filter')
    parser.add_argument('-r', '--report', action="store_true",
                        dest='make_report',
                        help='make report after program finish')
    parser.add_argument('-d', default = '', dest="dest_path",
                        help='destination path to report')
    return parser
