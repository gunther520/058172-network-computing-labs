#!/usr/bin/env python3
#
# Copyright (c) Networked Systems Group (NSG) ETH Zürich.
# All Rights Reserved.
from scapy.all import Ether, IP, sendp, get_if_hwaddr, get_if_list, TCP, Raw, UDP
import sys, socket, random
import argparse

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def send_random_traffic(dst_ip, num_packets, type):

    dst_addr = '10.0.1.2'
    total_pkts = 0
    random_port = random.randint(1024,65000)
    print(random_port)
    iface = get_if()
    #For this exercise the destination mac address is not important. Just ignore the value we use.
    p = Ether(dst="00:00:0a:00:00:01", src=get_if_hwaddr(iface)) / IP(dst=dst_addr,proto=4)
    if type == "UDP":
        p = p / UDP(sport=random_port,dport=3000)
    elif type=="TCP":
        p = p / TCP(dport=random_port)
    else:
        p=p / IP(dst="10.0.1.1")/UDP(sport=random_port,dport=3000)

    del p.chksum
    p=p.__class__(bytes(p))
    p.show()
    for _ in range(num_packets):
        sendp(p, iface = iface)
        total_pkts += 1
    print("Sent %s packets in total" % total_pkts)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Script to send packets to a specific destination')
    parser.add_argument("-d", "--destination", required=False, type=str, help="The IP address of the destination")
    parser.add_argument("-p", "--packets", type=int, required=True, help="Number of packets to send")
    parser.add_argument("-t", "--type", type=str, required=True, help="Type of packet to send", choices=["UDP", "TCP","IP-in-IP"], default="TCP")

    args = parser.parse_args()

    dst_name = args.destination
    num_packets = args.packets
    type = args.type
    send_random_traffic(dst_name, num_packets, type)