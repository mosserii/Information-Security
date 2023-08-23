import time
import os
from scapy.all import *


WINDOW = 60
MAX_ATTEMPTS = 15

IP_syn_times = {} #<IP, [time entries]> 
blocked = set()  # We keep blocked IPs in this set


def on_packet(packet):
    """This function will be called for each packet.

    Use this function to analyze how many packets were sent from the sender
    during the last window, and if needed, call the 'block(ip)' function to
    block the sender.

    Notes:
    1. You must call block(ip) to do the blocking.
    2. The number of SYN packets is checked in a sliding window.
    3. Your implementation should be able to efficiently handle multiple IPs.
    """
    
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return
        
    src_ip = packet[scapy.all.IP].src
    if is_blocked(src_ip):
        return
    if packet[scapy.all.TCP].flags != "S": #not a SYN packet
        return
    
    current_time = time.time()

    if src_ip in IP_syn_times:
        IP_syn_times[src_ip].append(current_time)
        while (current_time - IP_syn_times[src_ip][0] > WINDOW):#clean the list
            IP_syn_times[src_ip].pop(0) #remove first element in times list
        
        if len(IP_syn_times[src_ip]) > MAX_ATTEMPTS:
            block(src_ip)
    
    else :
        IP_syn_times[src_ip] = [current_time]
        #we only have 1 syn_call from this IP for now, so no blocking


def generate_block_command(ip: str) -> str:
    """Generate a command that when executed in the shell, blocks this IP.

    The blocking will be based on `iptables` and must drop all incoming traffic
    from the specified IP."""
    #iptables -A INPUT -s <IP_ADDRESS> -j DROP
    # todo return f"iptables -A INPUT -p tcp -s {ip} -d 0/0 -j DROP"
    return "iptables -A INPUT -s " + ip +" -j DROP"


def block(ip):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    os.system(generate_block_command(ip))
    blocked.add(ip)


def is_blocked(ip):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    return ip in blocked


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    sniff(prn=on_packet)


if __name__ == '__main__':
    main()
