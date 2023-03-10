import dpkt
import socket

f = open('assignment2.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

def convMac(address):
    return ":".join("{:02x}".format(b) for b in address)

recPort = 80
flows = {}
time={}
congest={}

print("PART A \n --------------------------------------------------------------")
for ts, bf in pcap:
    eth = dpkt.ethernet.Ethernet(bf)
    if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP):
        tcp = eth.data.data
        srcPort = tcp.sport
        dstPort = tcp.dport
        srcIp = socket.inet_ntoa(eth.data.src)
        dstIp = socket.inet_ntoa(eth.data.dst)
        key = (srcIp, dstIp, srcPort, dstPort)
        if key in flows:
            if flows[key]['firstPkt']:
                flows[key]['ack'] = tcp.ack
                flows[key]['winSize'] = tcp.win
                flows[key]['cwnd'] = 1
                flows[key]['firstPkt'] = False
                flows[key]['seqNums'] = [tcp.seq]
                flows[key]['ackNums'] = [tcp.ack] 
                flows[key]['windowSizes'] = [tcp.win]
            else:
                flows[key]['bytes'] += len(tcp.data)
                flows[key]['lastSeen'] = ts
                flows[key]['seqNums'].append(tcp.seq)
                flows[key]['ackNums'].append(tcp.ack) 
                flows[key]['windowSizes'].append(tcp.win)
                flows[key]['ack'] = tcp.ack
                flows[key]['winSize'] = tcp.win
        else:
            flows[key] = {'bytes': len(tcp.data), 'startTime': ts, 'lastSeen': ts, 'firstPkt': True, 'ack': 0, 'winSize': 0, 'seqNums': [], 'ackNums': [], 'windowSizes': []}
            flows[key]['seqNums'].append(tcp.seq) 
            flows[key]['ackNums'].append(tcp.ack)
            flows[key]['windowSizes'].append(tcp.win)
        if tcp.flags == 2:
            if tcp.sport not in time:
                time[tcp.sport] = []
            time[tcp.sport].append(ts)
        elif tcp.flags == 17 and tcp.sport == recPort:
            if tcp.dport in time:
                time[tcp.dport].append(ts)
        elif tcp.flags == 24 and tcp.sport != recPort:
            if tcp.sport not in congest:
                congest[tcp.sport] = []
            if len(congest[tcp.sport]) < 2:
                congest[tcp.sport].extend([ts, False])
        elif tcp.flags == 16 and tcp.sport == recPort:
            if tcp.dport in congest and not congest[tcp.dport][1]:
                congest[tcp.dport][0] = ts - congest[tcp.dport][0]
                congest[tcp.dport][1] = True
                congest[tcp.dport].append(0)
    

f.close()

count = 0
f2 = open('assignment2.pcap','rb')
pcap = dpkt.pcap.Reader(f2)
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    if tcp.flags!=2 and tcp.sport != recPort:
        if len(tcp)>0:
            if(len(congest[tcp.sport])<3):
                continue
            elif (congest[tcp.sport][2]==0 and len(congest[tcp.sport])<6 and len(tcp.data)>0):
                congest[tcp.sport][2]=ts
                congest[tcp.sport].append(1)
            elif (congest[tcp.sport][2]<=ts and ts <= congest[tcp.sport][2]+congest[tcp.sport][0]) and len(tcp.data)>0:
                congest[tcp.sport][len(congest[tcp.sport])-1]+=1
            elif (congest[tcp.sport][2]>ts or ts > congest[tcp.sport][2]+congest[tcp.sport][0]):
                congest[tcp.sport][2]=0
    count+=1



print("TCP FLOW: \n --------------------------------------------------------------")
j = 1
for key in flows:
    if j >= 4:
        break
    duration = (flows[key]['lastSeen'] - flows[key]['startTime']) / 1.0
    throughput = flows[key]['bytes'] / duration
    if throughput == 0:
        continue;
    print(f"Flow {j}: ")
    print(f"Source Port: {key[2]}\tSource IP Address: {key[0]}")
    print(f"Destination Port: {key[3]} \tDestination IP Address: {key[1]}")
    print(f"Throughput: {throughput:.2f}, bytes/s ")
    j += 1

k = 1
for key in flows: 
    if k >= 4:
        break
    duration = (flows[key]['lastSeen'] - flows[key]['startTime']) / 1000000.0
    throughput = flows[key]['bytes'] / duration
    if throughput == 0:
        continue;
    print(f"\nFirst two transaction after TCP connection for flow {k}  \n --------------------------------------------------------------")
    for j in range(2):
        print(f"Transaction {j+1}:")
        print(f"Sender Seq number: {flows[key]['seqNums'][j]}")
        print(f"Ack number: {flows[key]['ackNums'][j]}")
        print(f"Window size: {flows[key]['windowSizes'][j]}")
        print(f"Receiver Seq number: {flows[key]['ackNums'][j]}")
        print(f"Ack number: {flows[key]['seqNums'][j]}")
        print(f"Window size: {flows[key]['windowSizes'][j]}\n")
    k += 1


print("PART B \n --------------------------------------------------------------")
print("First 3 congestion windows of each flow")
m = 1
for val in congest:
    print("port:", val)
    print(f"Window size {m}: {congest[val][3]}, {congest[val][4]}, {congest[val][5]}")
    m += 1 

f2.close()

duplicates={}

f3 = open('assignment2.pcap','rb')
pcap3 = dpkt.pcap.Reader(f3)

for ts, buf in pcap3:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    if tcp.flags==2:
        duplicates[tcp.sport]={}
    elif tcp.flags==16 and tcp.sport == recPort:
        duplicate = list(duplicates[tcp.dport].keys())
        if not tcp.ack in duplicate:
            duplicates[tcp.dport][tcp.ack]=0
        else:
            duplicates[tcp.dport][tcp.ack]+=1

print("\nTriple Duplicate ACKS and Timeout \n --------------------------------------------------------------")
n = 1
for val in duplicates:
    timeout = 0
    triple = 0
    for val2 in duplicates[val]:
        if (duplicates[val][val2]>0):
            timeout += 1
        if(duplicates[val][val2]>84):
            triple += 1
    print("port:", val)
    print("Triple Duplicate ACK: ",triple)
    print("Timeout: ",timeout)

f3.close()