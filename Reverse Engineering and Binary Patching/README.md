### **Reverse Engineering and Binary Patching**


`Q1: A program that validates files using some logic. `
1. Reverse Engineer the "msgcheck" program using IDA PRO.
2. Write a python script to fix .msg files (a minimal change) so that they become valid! - just changing variables so the program will skip the loop that check the validity of messages.
3. Same as (2), but this time we do enter the loop, just that now we change the first byte of the message and it will be valid because we xor twice with the same value and the message will pass the validity check (see more in q1c.txt).
4. This time, patch the program itself instead of fixing the messages : one can patch the binary of msgcheck so that instead of JNZ (conditional jump), we will have JMP (unconditional jump) and therefore each message will pass as valid!
5. Again patching the program binary, this time changing the return value to be 0 (valid) every time, so even if it is invalid, we will return 0 instead of 1.

`Q2: Patch the binary of readfile, a program that reads line by line, so that it will execute lines beginning with a #! `
- find deadzones where you can patch the code, figure out the offset of these zones using IDA. 
Implement in Assembly each of the patches (patch1.asm, patch2.asm).
- the malicious code checks if the string starts with `#!` or not.
- if it does, call system with the command after #! and then jump after printf (we do not want the commands to be printed).
See more in q2.txt