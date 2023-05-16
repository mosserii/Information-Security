### **ROP - Return Oriented Programming**

In this exercise, we do not write code into the stack because back in 2005 these attacks became much harder to use.
therefore, we implement attacks that are called : ROP and Return-to-libc.
*we spend a lot of time using gdb in this exercise.

Q1 : 
return to libc attack, see more in q1 files.

Q2 : 
We implement a search engine for ROP gadgets (a sequence of instructions; RET), this engine can search the memory and even supports searching for the same instruction with multiple combinations of registers at once.
SEE MORE in search.py, it is very cool!

Q3 : 
A simple ROP "Write-gadget", see more in q3.py and q3.txt

Q4 : 
A much more sophisticated ROP attack that will cause the sudo program to run in an endless loop and print whatever we want!