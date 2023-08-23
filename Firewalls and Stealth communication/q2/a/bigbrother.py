from scapy.all import *


LOVE = 'love'
unpersons = set()


def spy(packet):
    """Check for love packets.

    For each packet containing the word 'love', add the sender's IP to the
    `unpersons` set.

    Notes:
    1. Use the global LOVE as declared above.
    """
    if not packet.haslayer(scapy.all.TCP) or not packet.haslayer(scapy.all.IP):
        return 
    payload = str(packet[scapy.all.TCP].payload)
    if LOVE in payload:
        sender_IP = packet[scapy.all.IP].src
        unpersons.add(sender_IP)
        
    
    


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    sniff(iface=get_if_list(), prn=spy)


if __name__ == '__main__':
    main()
