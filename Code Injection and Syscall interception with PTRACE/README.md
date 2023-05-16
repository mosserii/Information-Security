### **Code Injection and Syscall interception with PTRACE**

In this exercise, we use ptrace functionality. we have a C&C (Command and Control) server controlling the malware, and an antivirus attempting to detect the malware. From the C&C server, we send commands to the malware, to modify the execution of the antivirus, so the antivirus will no longer see our virus!
We will use both code injection and syscall interception in order to sabotage the detection efforts of the antivirus.

Q1 : 
Find the Antivirus process' pid, and kill it (it works, but pretty crude).

Q2 :
Overwrite the "check_if_virus" function in the Antivirus so it will always return 0 (=no viruses).
We want to change the binary, so we put before compilation a global variable pid = 0x01234567 and then we compile and find it and replace it with the address of check_if_virus.

Q3 : 
The library "libvalidator.so" might get updated and the opcodes might change, this time we Overwrite the "check_if_virus" GOT entry with a different function (with the same signature).

Q4 : 
This time, we intercept every syscall so that if it is a read systemcall, as the antivirus would like to read each file and search for malware.
so if it is a read syscall, we change the edx register (the desired len) to 0 so the syscall will return without even checking the file. 

