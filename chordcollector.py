#!/usr/bin/env python
from __future__ import print_function
from scapy.all import *
import sys
import numpy

host_list = []
input_file = sys.argv[1]

def get_src_dst_pairs(all_packets):
    """ Takes in tcpdump formatted output (file) and counts the number of connections between hosts"""
    d = {}

    for packet in all_packets:
        try:
            # for IP packets, create unique host list for index offset reference
            if packet.haslayer(IP) == 1:
                if packet[1].src not in host_list:
                    host_list.append(packet[1].src)
                if packet[1].dst not in host_list:
                    host_list.append(packet[1].dst)
            else:
                continue

            # These are sorted to get a single count of interactions, rather than a->b, b->a
            ips = sorted([packet[1].src, packet[1].dst])
            conn = "{}>{}".format(ips[0], ips[1])
            if conn in d.keys():
                d[conn] = d[conn] + 1
            else:
                d[conn] = 1

        except AttributeError:
            continue
    return d

def populate_array(array, data_map, source_data):
    for conn, count in source_data.items():
        host_a, host_b = conn.split('>')
        x = data_map.index(host_a)
        y = data_map.index(host_b)
        array[x, y] = count
    return array

# Read binary .pcap file from tcpdump
print("Loading pcap... ", end='')
try:
	all_packets = rdpcap(input_file)
except:
	print("Error reading pcap file.")
	sys.exit(1)
print("done.")

# Take scapy formatted array of all packet data and extract src>dst counts
print("Processing pcap... ", end='')
connections = get_src_dst_pairs(all_packets)
print("done.\n")

# Sort and print list of unique hosts 
host_list.sort()
print("List of hosts:\n {}\n".format(host_list))

# Create, populate and print 2d array for all packet counts
data_array = numpy.zeros((len(host_list), len(host_list)))
output = populate_array(data_array, host_list, connections)
print("Populated array:\n {}\n".format(output.tolist()))