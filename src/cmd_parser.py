from argparse import ArgumentParser


def configure_parser():
    parser = ArgumentParser(description="sniff your traffic <3")
    parser.add_argument('-i', '--interface', dest='interface')
    parser.add_argument('-f', '--file', dest='filename')
    parser.add_argument('-c', '--console', dest='console_mode',
                        action='store_true')
    parser.add_argument('-d', '--debug', action='store_true',
                        dest='debug')
    parser.add_argument('--filter', dest='filter_exr')
    parser.add_argument('-l', '--filter-list', action='store_true',
                        dest='show_filter_list')
    return parser.parse_args()