import dpkt
import datetime
import socket

f = open('assignment2.pcap',  'rb')
pcap = dpkt.pcap.Reader(f)

def convMac(address):
    return ":".join("{:02x}".format(b) for b in address)

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

for ts, bf in pcap:
    print('Time Stamp: ', str(datetime.datetime.utcfromtimestamp(ts)))
    eth = dpkt.ethernet.Ethernet(bf)
    print('Ethernet Frame:')
    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            srcPort = tcp.sport
            dstPort = tcp.dport
            srcIp = socket.inet_ntoa(ip.src)
            dstIp = socket.inet_ntoa(ip.dst)
            print(f"Source IP: {srcIp}, Source Port: {srcPort}")
            print(f"Destination IP: {dstIp}, Destination Port: {dstPort}")
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
            print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
              (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
            if tcp.flags & dpkt.tcp.TH_SYN:
                print("SYN packet")
            elif tcp.flags & dpkt.tcp.TH_ACK:
                print("ACK packet")
                print(f"Sequence number: {tcp.seq}")
                print(f"Acknowledgement number: {tcp.ack}")
                print(f"Receive Window size: {tcp.win}")
            else:
                print("Not a SYN or ACK packet")
            
            if tcp.flags & dpkt.tcp.TH_SYN:
                total_bytes = 0
                start_time = ts
            elif tcp.flags & dpkt.tcp.TH_ACK:
                total_bytes += len(tcp.data)
                elapsed_time = ts - start_time
                if elapsed_time > 0:
                    throughput = total_bytes / elapsed_time
                    print(f"Throughput:", throughput, "bps")
                    print()
                else:
                    print("Throughput: N/A\n")

f.close()
