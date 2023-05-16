#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


int pid = 0x01234567;
int func_loc = 0x01230123;


int main() {

    int MOV_EAX_0 = 0x000000b8;
    int RET = 0xc300;
    
    
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
        perror("attach failed");
        return -1;
    }
    

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)){
        return -1;
    }

    //override 
    if (ptrace(PTRACE_POKEDATA, pid, func_loc, MOV_EAX_0) == -1){
        perror("write failed");
        return -1;
    }

    //override 
    if (ptrace(PTRACE_POKEDATA, pid, func_loc + 4, RET) == -1){
        perror("write failed");
        return -1;
    }


    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1){
        perror("detach failed");
        return -1;
    }
    return 0;
}

