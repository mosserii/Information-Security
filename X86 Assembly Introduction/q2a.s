# Declare the assembly flavor to use the intel syntax.
.intel_syntax noprefix

# Define a symbol to be exported from this file.
.global my_function

# Declare symbol type to be a function.
.type my_function, @function

# Code follows below.

my_function:
    #this function is used to get the input and transfer to SQUARED_FIBO  
    #if n <= 0 return 0 
    #if n == 1 return 1
    #else : return SQUARED_FIBO(n-1)^2 + SQUARED_FIBO(n-2)^2
    
    PUSH EBP
    MOV EBP, ESP
    
    MOV EBX, DWORD PTR [ESP + 8] #we had a push instruction so N is in ESP+8
    
    CMP EBX, 1 #n == 1
    MOV EAX, 1
    JE final   
    
    CMP EBX, 0 # n == 0
    MOV EAX, 0
    JLE final
    

    
RECURSE: 

    #n-1
    DEC EBX #N -= 1
    PUSH EBX #store original n : now n-1
    
    CALL my_function
    
    POP EBX #load original n : now n-1
    IMUL EAX, EAX #SQUARED_FIBO(n-1) ^ 2
    MOV ECX, EAX
    PUSH ECX

    #n-2
    DEC EBX #N-1 -= 1
    MOV EDX, EBX
    PUSH EBX #sp+8
    
    CALL my_function
    POP EDX #so we can get the second value in the stack into ECX
    
    POP ECX #todo big check
    IMUL EAX, EAX #SQUARED_FIBO(n-2) ^ 2
    ADD EAX, ECX #SQUARED_FIBO(n-1) ^ 2 + SQUARED_FIBO(n-2) ^ 2
    
final:
    MOV ESP, EBP
    POP EBP
    RET

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    








    
    
