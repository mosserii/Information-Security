#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


int pid = 0x01234567;
int GOT = 0x89abcdef;
int func_loc = 0x01230123;

int main() {

    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
        perror("attach failed");
        return -1;
    }
    

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)){
        return -1;
    }

    //override : write func_loc to addr in GOT
    if (ptrace(PTRACE_POKEDATA, pid, GOT, func_loc) == -1){
        perror("write failed");
        return -1;
    }

    

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1){
        perror("detach failed");
        return -1;
    }
    return 0;
}
