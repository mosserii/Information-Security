import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import padding


def send_message(ip: str, port: int):
    """Send an *encrypted* message to the given ip + port.

    Julia expects the message to be encrypted, so re-implement this function accordingly.

    Notes:
    1. The encryption is based on AES.
    2. Julia and Winston already have a common shared key, just define it on your own.
    3. Mind the padding! AES works in blocks of 16 bytes.
    """
    
    
    connection = socket.socket()
    key = b'abcdefghijklmnop'
    
    plaintext = b'I love you'
    iv = bytes([random.randint(0, 0xFF) for i in range(16)])

    #pad the plaintext before encryption
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
        #Encrypt the plaintext with PKCS7 padding
    # Create an AES cipher object
    cipher_object = AES.new(key, AES.MODE_EAX, iv)
    ciphertext = iv + cipher_object.encrypt(padded_plaintext)

    try:
        connection.connect((ip, port))
        connection.send(ciphertext)
    finally:
        connection.close()


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    send_message('127.0.0.1', 1984)


if __name__ == '__main__':
    main()
