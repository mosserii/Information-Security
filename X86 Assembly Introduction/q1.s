# Declare the assembly flavor to use the intel syntax.
.intel_syntax noprefix

# Define a symbol to be exported from this file.
.global my_function

# Declare symbol type to be a function.
.type my_function, @function

	# Code follows below.



my_function:
     MOV EBX, DWORD PTR [ESP + 4]
     MOV EAX, 0 #$ra
     CMP EBX, 1
     JL _FAILURE
     MOV ECX, 0 #i = 0
_LOOP:
     MOV EAX, ECX
     IMUL EAX, ECX
     CMP EAX, EBX
     JE _SUCCESS #EAX == EBX
     INC ECX
     CMP EAX, EBX
     JL _LOOP #EAX < EBX

     #if EAX > BAX : FAILURE, else : return EAX value
_SUCCESS:
     CMP EAX, EBX
     JG _FAILURE
     MOV EAX, ECX #$ra = sqrt(EBX)
     RET

_FAILURE: 
     MOV EAX, 0
     RET


