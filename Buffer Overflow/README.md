### **Buffer Overflow**

#### **`In this exercise we use IDA, gdb in order to find addresses in program memory!**`
Q1 :
- We want to Privilege Escalation ourselves in order to become root, but we do not know the password, so we need to find different ways.
- The main of the sudo program limits the length of the password but actually if we look carefully, we can see that with a password of length 10 we get a **`buffer overflow`**.
- The function check_password put variable auth just before "buff" and therefore as one can see in IDA, auth is located just above buff and therefore, when we concat buff (after putting 11 elements in it + NULL terminator), with a password of size 10, we run over auth and therefore, if the last char of password of length 10 is '1', we get that auth == 1 and the check of strcmp does not matter, we get authintecated.

Q2:
- The functions of C are not always safe, and therefore a good programmer should check length and be careful of leaving vulnerabilities to exploit.
- In this question, we exploit the vulnerability of the function strcat.
- We override the return address of the function so that it will return to our shellcode (including nops slide) and therefore will execute whatever we want, here we will show the ability to open a shell.
- See more in q2a.txt, shellcode.asm and q2b.txt!