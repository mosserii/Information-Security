import addresses
from infosec.core import assemble
from typing import Tuple, Iterable
import string
import itertools
import re



GENERAL_REGISTERS = [
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'
]


ALL_REGISTERS = GENERAL_REGISTERS + [
    'esp', 'eip', 'ebp'
]


class GadgetSearch(object):
    def __init__(self, dump_path: str, start_addr=None):
        """
        Construct the GadgetSearch object.

        Input:
            dump_path: The path to the memory dump file created with GDB.
            start_addr: The starting memory address of this dump. Use
                        `addresses.LIBC_TEXT_START` by default.
        """
        self.start_addr = (start_addr if start_addr is not None
                           else addresses.LIBC_TEXT_START)
        with open(dump_path, 'rb') as f:
            self.dump = f.read()



    def get_format_count(self, gadget_format: str) -> int:
        """
        Get how many different register placeholders are in the pattern.

        Examples:
            self.get_format_count('POP ebx')
            => 0
            self.get_format_count('POP {0}')
            => 1
            self.get_format_count('XOR {0}, {0}; ADD {0}, {1}')
            => 2
        """
        # Hint: Use the string.Formatter().parse method:
        #
        #   import string
        #   print string.Formatter().parse(gadget_format)

        cnt = 0
        my_set = set()
        for param in string.Formatter().parse(gadget_format):
            if param[1] is not None:
                my_set.add(param[1])
        
        return len(my_set)

    def get_register_combos(self, nregs: int, registers: Tuple[str]) -> Iterable[Iterable[str]]:
        """
        Return all the combinations of `registers` with `nregs` registers in
        each combination. Duplicates ARE allowed!

        Example:
            self.get_register_combos(2, ('eax', 'ebx'))
            => [['eax', 'eax'],
                ['eax', 'ebx'],
                ['ebx', 'eax'],
                ['ebx', 'ebx']]
        """

        return list(map(list,itertools.product(registers, repeat=nregs)))





    def format_all_gadgets(self, gadget_format: str, registers: Tuple[str]) -> Iterable[str]:
        """
        Format all the possible gadgets for this format with the given
        registers.

        Example:
            self.format_all_gadgets("POP {0}; ADD {0}, {1}", ('eax', 'ecx'))
            => ['POP eax; ADD eax, eax',
                'POP eax; ADD eax, ecx',
                'POP ecx; ADD ecx, eax',
                'POP ecx; ADD ecx, ecx']
        """
        # Hints:
        #
        # 0. Use the previous functions to count the number of placeholders,
        #    and get all combinations of registers.
        #
        # 1. Use the `format` function to build the string:
        #
        #    'Hi {0}! I am {1}, you are {0}'.format('Luke', 'Vader')
        #    => 'Hi Luke! I am Vader, you are Luke'
        #
        # 2. You can pass a list of arguments instead of specifying each
        #    argument individually. Use the internet, the force is strong with
        #    StackOverflow.
        format_count = self.get_format_count(gadget_format)
        
        r_combos = self.get_register_combos(format_count, registers)
       
        
        res = [gadget_format.format(*small) for small in r_combos]
        
        
        return res
        
        
        


    def find_all(self, gadget: str) -> Iterable[int]:
        """
        Return all the addresses of the gadget inside the memory dump.

        Example:
            self.find_all('POP eax')
            => < all ABSOLUTE addresses in memory of 'POP eax; RET' >
        """
        # Notes:
        #
        # 1. Addresses are ABSOLUTE (for example, 0x08403214), NOT RELATIVE to
        #    the beginning of the file (for example, 12).
        #
        # 2. Don't forget to add the 'RET'.

        res = []       
        gadget_plus_RET = gadget + "; RET"
        GADG_bytes = assemble.assemble_data(gadget_plus_RET)
        
        for i in range(len(self.dump)):
            bool_flag = 1
            for j in range(len(GADG_bytes)):
                if GADG_bytes[j] != self.dump[i+j]:
                    #current offset i does not match
                    bool_flag = 0 
                    break
            if bool_flag == 1:
                #res.append(format(self.start_addr + i, 'x'))
                res.append((self.start_addr + i))

        return res




    def find(self, gadget: str, condition=None) -> int:
        """
        Return the first result of find_all. If condition is specified, only
        consider addresses that meet the condition.
        """
        condition = condition or (lambda x: True)
        try:
            return next(addr for addr in self.find_all(gadget)
                        if condition(addr))
        except StopIteration:
            raise ValueError("Couldn't find matching address for " + gadget)


    def find_all_formats(self, gadget_format: str,
                         registers: Iterable[str] = GENERAL_REGISTERS) -> Iterable[Tuple[str, int]]:
        """
        Similar to find_all - but return all the addresses of all
        possible gadgets that can be created with this format and registers.
        Every element in the result will be a tuple of the gadget string and
        the address in which it appears.

        Example:
            self.find_all_formats('POP {0}; POP {1}')
            => [('POP eax; POP ebx', address1),
                ('POP ecx; POP esi', address2),
                ...]
        """
        
        res = []
        possible_gadgets = self.format_all_gadgets(gadget_format, registers)
        
        for gadget in possible_gadgets:
            addresses_for_gadget = self.find_all(gadget)
            for address in addresses_for_gadget:
                res.append((gadget, address))
        
        return res   
            
        

    def find_format(self, gadget_format: str,
                    registers: Iterable[str] = GENERAL_REGISTERS,
                    condition=None) -> Tuple[str, int]:
        """
        Return the first result of find_all_formats. If condition is specified,
        only consider gadget-address tuples that meet the condition.
        """
        condition = condition or (lambda x: True)
        try:
            return next(
                gadget_addr for gadget_addr in self.find_all_formats(gadget_format, registers)
                if condition(gadget_addr)
            )
        except StopIteration:
            raise ValueError(
                "Couldn't find matching address for " + gadget_format)
