jmp 100 #jump over patch
push edx
movzx edx, byte ptr [eax] #get first char
cmp edx, '#'
pop edx
jnz 109 #not "#!" so we jump *before* printf
push edx
movzx edx, byte ptr[eax+1]
cmp edx, '!'
pop edx
jnz 109 #not "#!" so we print jump *before* printf # if we are here, current line starts with "#!"
add eax, 2 #we want to pass to system just command, without #!
push eax             # _system(const char *string)
call -365 #_system func
jmp 132 #after printf


