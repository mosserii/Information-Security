import math
from scapy.all import *
import string


LOVE = 'love'
unpersons = set()


def spy(packet):
    """Check for love packets and encrypted packets.

    For each packet containing the word 'love', or a packed which is encrypted,
    add the sender's IP to the `unpersons` set.

    Notes:
    1. Use the global LOVE as declared above.
    """
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return
         
    payload = str(packet[scapy.all.TCP].payload)
    entropy = shannon_entropy(payload)
    
    if entropy > 3.0 or LOVE in payload:
        sender_IP = packet[scapy.all.IP].src
        unpersons.add(sender_IP)


def shannon_entropy(string: str) -> float:
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    distribution = [float(string.count(c)) / len(string)
                    for c in set(string)]
    return -sum(p * math.log(p) / math.log(2.0) for p in distribution)


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    sniff(iface=get_if_list(), prn=spy)


if __name__ == '__main__':
    main()
