# Declare the assembly flavor to use the intel syntax.
.intel_syntax noprefix

# Define a symbol to be exported from this file.
.global my_function

# Declare symbol type to be a function.
.type my_function, @function

# Code follows below.

my_function:
    
    PUSH EBP
    MOV EBP, ESP
    
    MOV EBX, DWORD PTR [ESP + 8] #get n
    
    CMP EBX, 1
    MOV EAX, 1 
    JE FINAL
    
    CMP EBX, 0
    MOV EAX, 0
    JLE FINAL 

    MOV EDX, 0 #An-2
    MOV ECX, 1 #An-1
 
 # EAX = RESULT = 0 here 
 
LOOP_ONE:

    DEC EBX #n--
    MOV EAX, 0
    
    IMUL EDX, EDX
    ADD EAX, EDX #RESULT += An_2^2
    MOV EDX, ECX #An_2 = An_1 before multiplication
    
    IMUL ECX, ECX
    ADD EAX, ECX #RESULT += An_1^2
    
    MOV ECX, EAX #An_1 = result
    

    CMP EBX, 1 
    JG LOOP_ONE #loop while n > 1
    

FINAL:
    MOV ESP, EBP
    POP EBP
    RET
    
    
    

    
    
    
    
    
    
