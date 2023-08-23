import socket
import math
import scapy.all as S

SRC_PORT = 65000

def break_into_triplets(string):
    triplets = []
    for char in string:
        binary_value = bin(ord(char))[2:]
        binary_value = '0' * (9 - len(binary_value)) + binary_value  # Pad with leading zeros to ensure 9 bits
        for i in range(0, len(binary_value), 3):
            triplet = binary_value[i:i+3]
            triplets.append(triplet)
    return triplets





def send_message(ip: str, port: int):
    """Send a *hidden* message to the given ip + port.

    Julia expects the message to be hidden in the TCP metadata, so re-implement
    this function accordingly.

    Notes:
    1. Use `SRC_PORT` as part of your implementation.
    """

    message = 'I love you'
    broken_message = break_into_triplets(message)
    num_of_packets = len(broken_message)
    
    for i in range(num_of_packets):     
        packet = S.IP(dst=ip)/S.TCP(sport=SRC_PORT, dport=port, reserved=int(broken_message[i], 2), flags="SA", seq=i, ack=num_of_packets)
    
        S.send(packet)


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    send_message('127.0.0.1', 1984)


if __name__ == '__main__':
    main()
