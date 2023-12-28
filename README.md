# Sniffer

## Usage
```
usage: sniffer.py [-h] [-i INTERFACE] [-f FILENAME] [-v] [--filter FILTER_EXPR] [-l] [-r] [-d DEST_PATH]

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
  -r, --report          make report after program finish
  -d DEST_PATH          destination path to report

```

## Состав проекта

* В папке protocols находятся классы, инкапсулирующие сущность сетевого пакета
  (например, IPPacket, TCPPacket). Пакеты более низкого уровня по заголовкам
  определяют пакет более высокого уровня и создают объект, который отвечает за
  этот пакет. Затем этот объект парсит заголовки пакета и определяет протокол
  следующего уровня. Если пакет не удаётся определить, он записывается в объект
  RawPacket, который представляет сырые данные
* В файле cmd_parser.py находится логика по обработке аргументов утилиты
* В файле filter.py находятся методы для фильтрации пакетов
* В файле report_maker.py находится метод make_report, который отвечает 
  за формирование html отчёта
* Файл sniffer.py является точкой входа в программу