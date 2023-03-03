import dpkt
import datetime
import socket

f = open('assignment2.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

def convMac(address):
    return ":".join("{:02x}".format(b) for b in address)

flows = {}

for ts, bf in pcap:
    eth = dpkt.ethernet.Ethernet(bf)
    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            srcPort = tcp.sport
            dstPort = tcp.dport
            srcIp = socket.inet_ntoa(ip.src)
            dstIp = socket.inet_ntoa(ip.dst)
            key = (srcIp, dstIp, srcPort, dstPort)
            if key in flows:
                if flows[key]['first_pkt']:
                    flows[key]['ack'] = tcp.ack
                    flows[key]['win_size'] = tcp.win
                    flows[key]['first_pkt'] = False
                    flows[key]['seq_nums'] = [tcp.seq]
                    flows[key]['ack_nums'] = [tcp.ack] 
                    flows[key]['window_sizes'] = [tcp.win]
                else:
                    flows[key]['bytes'] += len(tcp.data)
                    flows[key]['last_seen'] = ts
                    flows[key]['seq_nums'].append(tcp.seq)
                    flows[key]['ack_nums'].append(tcp.ack) 
                    flows[key]['window_sizes'].append(tcp.win)
            else:
                flows[key] = {'bytes': len(tcp.data), 'start_time': ts, 'last_seen': ts, 'first_pkt': True, 'ack': 0, 'win_size': 0, 'seq_nums': [], 'ack_nums': [], 'window_sizes': []}
                flows[key]['seq_nums'].append(tcp.seq) 
                flows[key]['ack_nums'].append(tcp.ack)
                flows[key]['window_sizes'].append(tcp.win)

i = 1
print("TCP FLOW: \n --------------------------------------------------------------")
for key in flows:
    if i >= 4:
        break
    duration = (flows[key]['last_seen'] - flows[key]['start_time']) / 1000000.0
    throughput = flows[key]['bytes'] / duration
    if throughput == 0:
        continue;
    print(f"Flow {i}: ")
    print(f"Source Port: {key[2]}\tSource IP Address: {key[0]}")
    print(f"Destination Port: {key[3]} \tDestination IP Address: {key[1]}")
    print(f"Throughput: {throughput:.2f}, bytes/s ")
    i += 1

i = 1

for key in flows: 
    if i >= 4:
        break
    duration = (flows[key]['last_seen'] - flows[key]['start_time']) / 1000000.0
    throughput = flows[key]['bytes'] / duration
    if throughput == 0:
        continue;
    print(f"\nFirst two transaction after TCP connection for flow {i}  \n --------------------------------------------------------------")
    for j in range(2):
        print(f"Transaction {j+1}:")
        print(f"Seq number: {flows[key]['seq_nums'][j]}")
        print(f"Ack number: {flows[key]['ack_nums'][j]}")
        print(f"Window size: {flows[key]['window_sizes'][j]}")
    i += 1

f.close()