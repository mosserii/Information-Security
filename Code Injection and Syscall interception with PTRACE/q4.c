#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>

int pid = 0x01234567;

int main(int argc, char **argv) {
    // Make the malware stop waiting for our output by forking a child process:
    if (fork() != 0) {
        // Kill the parent process so we stop waiting from the malware
        return 0;
    } else {
        // parent process
        wait(NULL);

        struct user_regs_struct regs;
        long orig_eax;
        // attach to child process
        ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        waitpid(pid, NULL, 0);

        while (1) {
            // wait for next syscall
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            waitpid(pid, NULL, 0);

            // retrieve register values
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            orig_eax = regs.orig_eax;

            // modify edx register if eax is 3
            if (orig_eax == 3) {
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                regs.edx = 0;
                ptrace(PTRACE_SETREGS, pid, NULL, &regs);
            }

            // resume execution
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            waitpid(pid, NULL, 0);
        }

        // detach from child process
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        printf("Child process finished.\n");
    }

    return 0;
}
