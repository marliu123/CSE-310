import pyshark

def analysis():
    # Open the PCAPNG file
    
    capture = pyshark.FileCapture('assignment4_my_arp.pcapng')
    for packet in capture:
        if 'ARP' in packet:
            print(packet)
            break
    # Close the capture file
    capture.close()

analysis()