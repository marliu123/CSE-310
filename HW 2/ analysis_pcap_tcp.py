import dpkt
import datetime
import socket

f = open('assignment2.pcap',  'rb')
pcap = dpkt.pcap.Reader(f)


def convMac(address):
    return ":".join("{:02x}".format(b) for b in address)


for ts, bf in pcap:
    print('Time Stamp: ', str(datetime.datetime.utcfromtimestamp(ts)))
    eth = dpkt.ethernet.Ethernet(bf)
    print('Ethernet Frame:')
    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            src_port = tcp.sport
            dst_port = tcp.dport
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            print(f"Source IP: {src_ip}, Source Port: {src_port}")
            print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}\ns")
    