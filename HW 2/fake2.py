import dpkt
import os
pcapFile=os.path.join(os.getcwd(), 'assignment2.pcap')

# THE FOLLOWING CODE IS FOR THE PROGRAMMING ASSIGNMENT 02 (CSE 310 - PROF. JAIN)

f = open(pcapFile,'rb')
pcap = dpkt.pcap.Reader(f)
f2 = open(pcapFile,'rb')
pcap2 = dpkt.pcap.Reader(f2)
count = 0
flow = {}
times={}
congestion={}
sender='130.245.145.12'
receiver='128.208.2.198'
receiver_port = 80
duplicates={}
for ts, buf in pcap2:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    if tcp.flags==2:
        times[tcp.sport]= []
        congestion[tcp.sport]=[]
        times[tcp.sport].append(ts)
        duplicates[tcp.sport]={}
    elif tcp.flags==17 and tcp.sport == receiver_port:
        times[tcp.dport].append(ts)
    elif tcp.flags==24 and tcp.sport != receiver_port:
        if (len(congestion[tcp.sport])<2):
            congestion[tcp.sport].append(ts)
            congestion[tcp.sport].append(False)
    elif tcp.flags==16 and tcp.sport == receiver_port:
        if (not congestion[tcp.dport][1]):
            congestion[tcp.dport][0] = ts - congestion[tcp.dport][0]
            congestion[tcp.dport][1]=True
            congestion[tcp.dport].append(0)
        dups = list(duplicates[tcp.dport].keys())
        if not tcp.ack in dups:
            duplicates[tcp.dport][tcp.ack]=0
        else:
            duplicates[tcp.dport][tcp.ack]+=1

f2.close()

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    if tcp.flags==2:
        flow[tcp.sport] = {}
        flow[tcp.sport]['throughput']=0
    elif tcp.flags==16 and tcp.sport != receiver_port:
        if (len(flow[tcp.sport])==1):
            flow[tcp.sport]['win']=tcp.win
            flow[tcp.sport][tcp.seq]=tcp.ack
        elif(len(flow[tcp.sport])<5):    
            flow[tcp.sport][tcp.seq]=tcp.ack
            if len(tcp.data)>0:
                flow[tcp.sport]['throughput'] +=len(tcp)
        elif ts < times[tcp.sport][1] and len(tcp.data)>0:
            flow[tcp.sport]['throughput'] += len(tcp)
    elif tcp.flags !=16 and tcp.sport!= receiver_port:
        if ts < times[tcp.sport][1] and len(tcp.data)>0:
            flow[tcp.sport]['throughput']+=len(tcp)
    if tcp.flags!=2 and tcp.sport != receiver_port:
        if len(tcp)>0:
            if(len(congestion[tcp.sport])<3):
                continue
            elif (congestion[tcp.sport][2]==0 and len(congestion[tcp.sport])<6 and len(tcp.data)>0):
                congestion[tcp.sport][2]=ts
                congestion[tcp.sport].append(1)
            elif (congestion[tcp.sport][2]<=ts and ts <= congestion[tcp.sport][2]+congestion[tcp.sport][0]) and len(tcp.data)>0:
                congestion[tcp.sport][len(congestion[tcp.sport])-1]+=1
            elif (congestion[tcp.sport][2]>ts or ts > congestion[tcp.sport][2]+congestion[tcp.sport][0]):
                congestion[tcp.sport][2]=0
    count+=1

# this part is to calculate the throughputs for each flow

throughputs=[]
for value in times:
    throughputs.append(times[value][1]-times[value][0])

count=0
for value in flow:
    throughputs[count]=(flow[value]['throughput']/throughputs[count])
    count+=1

# this part is to print out the flows (source ip addresses, destination ip addresses, source port numbers, destination port numbers, and throughputs)

print('''
    ----------------------------------------------------------------------------------------------------
    |                                                                                                  |
    |                           PROGRAMMING ASSIGNMENT 02 - PART A - CHEN146                           |
    |                                                                                                  |
    ----------------------------------------------------------------------------------------------------
    | TCP FLOW | SOURCE IP ADDR. | DESTINATION IP ADDR. | SRC PORT | DEST. PORT |      THROUGHPUT      |
    ----------------------------------------------------------------------------------------------------''')

index = 1

for value in flow:
    print('    |    {ind}     | {source_ip}  |     {dest_ip}    |  {src_port}   |     {dest_port}     |  {throughput}  |'.format(ind=index, 
        source_ip=sender, dest_ip=receiver, src_port=value, dest_port=receiver_port, throughput=throughputs[index-1]))
    index+=1
print('    ----------------------------------------------------------------------------------------------------\n')

# this part is to print out each flow and the first two transactions after the TCP connection is set up (from sender to receiver)
# this includes the values of the sequence number, acknowledgement numbers, and window sizes
index=1

for value in flow:
    keyList = list(flow[value].keys())
    window = flow[value][keyList[1]]
    seqNum01 = keyList[2]
    ackNum01 = flow[value][seqNum01]
    seqNum02 = keyList[3]
    ackNum02 = flow[value][seqNum02]
    ackNum03 = keyList[4]
    print(f'''
                FIRST TWO TRANSACTIONS AFTER CONNECTION SETUP FOR FLOW {index}
    ------------------------------------------------------------------------------------------
    |          SOURCE  ==>  DESTINATION         |   (SEQ NUMBER, ACK NUMBER)  | WINDOW SIZE  |
    ------------------------------------------------------------------------------------------
    | {sender}:{value} ==> {receiver}:{receiver_port} | ( {seqNum01} , {ackNum01} ) |      {window}       |
    | {receiver}:{receiver_port} ==> {sender}:{value} | ( {ackNum01} , {seqNum02} ) |      {window}       |
    ------------------------------------------------------------------------------------------
    | {sender}:{value} ==> {receiver}:{receiver_port} | ( {seqNum02} , {ackNum02} ) |      {window}       |
    | {receiver}:{receiver_port} ==> {sender}:{value} | ( {ackNum02} , {ackNum03} ) |      {window}       |
    ------------------------------------------------------------------------------------------\n
    ''')
    index+=1

# printing part b values - congestion windows and other information

print('''
    ----------------------------------------------------------------------------------------------------
    |                                                                                                  |
    |                           PROGRAMMING ASSIGNMENT 02 - PART B - CHEN146                           |
    |                                                                                                  |
    ----------------------------------------------------------------------------------------------------
    ----------------------------------------------------------------------------------------------------
    |                                   CONGESTION WINDOWS                                             |
    ----------------------------------------------------------------------------------------------------
    |       PORT       |         CWND 01         |         CWND 02         |          CWND 03          |
    ----------------------------------------------------------------------------------------------------''')

for value in congestion:
    print('    |       {port}      |           {cwnd01}            |          {cwnd02}             |             {cwnd03}            |'.format(port=value,cwnd01=congestion[value][3],cwnd02=congestion[value][4],cwnd03=congestion[value][5]))
    print('    ----------------------------------------------------------------------------------------------------')

print('''
    ----------------------------------------------------------------------------------------------------
    |                                       RETRANSMISSIONS                                            |
    ----------------------------------------------------------------------------------------------------
    |       PORT       |         DUE TO TIMEOUT          |          DUE TO TRIPLE DUPLICATE ACKS       |
    ----------------------------------------------------------------------------------------------------''')

for value in duplicates:
    it = 0
    tr = 0 
    for value1 in duplicates[value]:
        if (duplicates[value][value1]>=1):
            it+=1
        if(duplicates[value][value1]>=85):
            tr+=1
    print(f'    |       {value}      |               {it}                 |                 {tr}                           |')
    print('    ----------------------------------------------------------------------------------------------------')
f.close()