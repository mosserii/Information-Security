import socket
from scapy.all import *

SRC_PORT = 65000
triplets = {}



def get_triplets(packet):
    
    triplet = (packet[scapy.all.TCP].reserved)
    triplet = bin(triplet)[2:]
    triplet = '0' * (3 - len(triplet)) + triplet
    seq_num = packet[scapy.all.TCP].seq
    triplets[seq_num] = triplet
    
def check_port(packet):
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return False  
    if packet[scapy.all.TCP].flags != "SA":
        return False 
    if packet[scapy.all.TCP].sport != SRC_PORT:
        return False
    return True
    
def stop_capture(packet):
    return packet[scapy.all.TCP].ack == len(triplets)
    


def receive_message(port: int) -> str:
    """Receive *hidden* messages on the given TCP port.

    As Winston sends messages encoded over the TCP metadata, re-implement this
    function so to be able to receive the messages correctly.

    Notes:
    1. Use `SRC_PORT` as part of your implementation.
    """
    
    sniff(lfilter=check_port, prn=get_triplets, stop_filter=stop_capture, iface=get_if_list())
    message = ""
    curr_letter = ""
    
    
    i = 0
    while i < len(triplets):
        try :
            curr_letter = triplets[i] + triplets[i+1] + triplets[i+2]
            i += 3
            message += chr(int(curr_letter, 2))
           
        except : 
            return ""
            
    return message


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    message = receive_message(1984)
    print('received: %s' % message)


if __name__ == '__main__':
    main()
