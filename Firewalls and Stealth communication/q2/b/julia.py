import socket
from Crypto.Cipher import AES
import random
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import padding

def receive_message(port: int) -> str:
    """Receive *encrypted* messages on the given TCP port.

    As Winston sends encrypted messages, re-implement this function so to
    be able to decrypt the messages.

    Notes:
    1. The encryption is based on AES.
    2. Julia and Winston already have a common shared key, just define it on your own.
    3. Mind the padding! AES works in blocks of 16 bytes.
    """
    
    key = b'abcdefghijklmnop'
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(('', port))
        listener.listen(1)
        connection, address = listener.accept()
        try:
            #the encrypted thing we received
            payload = (connection.recv(1024))
            iv = (payload[:16])
            encrypted_padded = (payload[16:])
            
            
            #decrypt the encrypted_padded message
            decipher = AES.new(key, AES.MODE_EAX, iv)
            decrypted_padded = decipher.decrypt(encrypted_padded)

            #unpad the decrypted_padded
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()

            return plaintext.decode("latin-1")
            
        finally:
            connection.close()
    finally:
        listener.close()


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    message = receive_message(1984)
    print('received: %s' % message)


if __name__ == '__main__':
    main()
