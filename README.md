# Sniffer

## Usage
```
usage: sniffer.py [-h] [-i INTERFACE] [-f FILENAME] [-v] [--filter FILTER_EXPR] [-l]

tool to sniff traffic

options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        network interface (default: any)
  -f FILENAME, --file FILENAME
                        path to .pcap file
  -v, --verbose         verbose mode
  --filter FILTER_EXPR  filter expression in format <protocol> or<protocol>.<header>==<value>, see sniffer.py -l to list available filters
  -l, --filter-list     available protocols and headers to filter

```