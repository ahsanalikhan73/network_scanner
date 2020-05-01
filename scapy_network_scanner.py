#!/usr/bin/env python
import scapy.all as scapy
import argparse
import requests
from bs4 import BeautifulSoup
import time

class Network_Scanner():
    
    def get_arguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-t', '--target', dest='target', help='Target IP / IP Range')
        values  = parser.parse_args()
        if not values.target:
            parser.error('===> [-] Please specify The Target!')
        return values

    def find_mac_vendor(self, mac):
        try:
            time.sleep(1)
            headers = {
                'Accept-Encoding': 'gzip, deflate, sdch',
                'Accept-Language': 'en-US,en;q=0.8',
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Referer': 'http://www.wikipedia.org/',
                'Connection': 'keep-alive',
                }

            url = 'http://api.macvendors.com/' + mac
            r = requests.get(url, headers=headers)
            soup = BeautifulSoup(r.text, 'html.parser')
            return soup
        except:
            print('[-] Not Found')

    def device_type(self, ip):
        packet = scapy.IP(dst=ip)/scapy.ICMP()
        response = scapy.sr1(packet, timeout=2, verbose=0)

        if response == None:
            return '\tUnknown'

        elif response.haslayer(scapy.IP):
            if response.getlayer(scapy.IP).ttl <= 64:
                return 'Linux|Android'
            else:
                return 'Windows'

    def scan(self, ip):
        arp_request = scapy.ARP(pdst=ip)    #create ARP packet
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') # create ethernet packet that will be send to every host in a  network
        combine_frames = broadcast/arp_request

        answered_list , unanswered_list = scapy.srp(combine_frames, timeout=1, verbose=False)
        client_list = []
        for element in answered_list:
            device = self.device_type(element[1].psrc)
            mac_vendor = self.find_mac_vendor(element[1].hwsrc)
            client_dict = {'ip':element[1].psrc, 'mac':element[1].hwsrc, 'vendor': mac_vendor, 'device':device}
            client_list.append(client_dict)
        return client_list      #returns a list of dictionaries


    def display_result(self, hosts):
        print('\n_______________________________________________________________________________________________\n')
        print('IP Addresses\t\tMAC Addresses\t\tMAC Vendor / Hostname\t\tDevice Type')
        print('-----------------------------------------------------------------------------------------------\n')
        for client in hosts:
            print(client['ip'] + '\t\t' + client['mac'] + '\t' + str(client['vendor']) + '\t\t' + client['device'])
        print('\n')


    def main(self):

        options = self.get_arguments()
        scan_result = self.scan(options.target) # List of dictionaries (IP + MAC)
            
        self.display_result(scan_result)



if __name__ == '__main__':
    scanner = Network_Scanner()
    scanner.main()