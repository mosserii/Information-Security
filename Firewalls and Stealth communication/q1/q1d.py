import scapy as scapy
from scapy.all import *


def on_packet(packet):
    """Implement this to send a SYN ACK packet for every SYN.

    Notes:
    1. Use *ONLY* the `send` function from scapy to send the packet!
    """
    
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return
        
    if packet[scapy.all.TCP].flags != "S": #not a SYN packet
        return
        
    ip_to_reply = packet[scapy.all.IP].src
    dst_port_to_reply = packet[scapy.all.TCP].sport
    from_ip = packet[scapy.all.IP].dst
    src_port_to_reply = packet[scapy.all.TCP].dport
    
    
    seq_number = packet[scapy.all.TCP].seq
    
    
    syn_ack_packet = scapy.all.IP(src=from_ip, dst=ip_to_reply) / scapy.all.TCP(sport=src_port_to_reply, dport=dst_port_to_reply, flags="SA", ack=seq_number+1)
    scapy.all.send(syn_ack_packet)


def main(argv):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    sniff(prn=on_packet)


if __name__ == '__main__':
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    import sys
    sys.exit(main(sys.argv))
