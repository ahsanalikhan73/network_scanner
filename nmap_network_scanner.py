#!/usr/bin/env python
import nmap
scanner = nmap.PortScanner()

print('\n[+] Scanning Your Network ...\n\n')
scanner.scan(hosts='192.168.0.1/24', arguments='-n -sP -PE -PA21,23,80,3389')
hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
for host, status in hosts_list:
    print(host + ' : ' +  status)

print('\n')