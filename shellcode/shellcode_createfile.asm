format PE console
use32
entry start
start:
    ; establish a new stack frame
    pushad
    push ebp
    mov ebp, esp

    sub esp, 0x18           ; alloc for local variables
    
    xor esi, esi
    pushw si                ; null terminated   2bytes
    push 0x41               ; 4 bytes
    pushw 0x656c            ; 2 bytes
    push 0x69466574         ; 4 bytes
    push 0x61657243         ; 4 bytes
    mov [ebp - 4], esp      ; var4 = "CreateFileA\x00"

    ; find kernel32.dll
    xor esi, esi
    mov ebx, [fs:0x30 + esi]
    mov ebx, [ebx + 0x0c]   ; &PEB_LDR_DATA
    mov ebx, [ebx + 0x14]   ; &InMemoryModuleList
    mov ebx, [ebx]          ; InMemoryOrderModuleList->next(ntdll.dll)
    mov ebx, [ebx]          ; InMemoryOrderModuleList->next->next(kernel32.dll)
    mov ebx, [ebx + 0x10]   ; InMemoryOrderModuleList->next->next->base
    mov [ebp - 8], ebx      ; var8 = kernel32.dll base address

    ; find CreateFileA Address
    mov eax, [ebx + 0x3c]   ; RVA of PE signature
    add eax, ebx            ; Address of PE signature
    mov eax, [eax + 0x78]   ; RVA of Export Table
    add eax, ebx            ; Address of Export Table

    mov ecx, [eax + 0x24]   ; RVA of Ordinal Table
    add ecx, ebx            ; address of Ordinal Table
    mov [ebp - 0x0c], ecx   ; var12 = address of Ordinal Table

    mov edi, [eax + 0x20]   ; RVA of Name Pointer Table
    add edi, ebx            ; address of Name Pointer Table
    mov [ebp - 0x10], edi   ; var16 = address of Name Pointer Table

    mov edx, [eax + 0x1c]   ; RVA of Address Table
    add edx, ebx            ; Address of Address Table
    mov [ebp - 0x14], edx   ; var20 = address of Address Table

    mov edx, [eax + 0x14]   ; Number of exported functions

    xor eax, eax            ; counter = 0
.loop:
    mov edi, [ebp - 0x10]   ; edi = var16 = address of Name Pointer Table
    mov esi, [ebp - 4]      ; esi = var4 = "WinExec\x00"
    xor ecx, ecx

    cld                     ; set DF = 0 process string left to right
    mov edi, [edi + eax * 4]; Entry of Name Pointer Table is 4 bytes long

    add edi, ebx            ; address of string
    add cx, 11               ; length to compare
    repe cmpsb              ; compare first 8 bytes in
                            ; esi and edi. ZF=1 if equal, ZF=0 if not
    jz start.found

    inc eax                 ; counter++
    cmp eax, edx            ; check if last function is reached
    jb start.loop

    add esp, 0x28           ; 0x18 + 2 + 4 + 2 + 4 + 4
    jmp start.end           ; not found, jmp to end
.found:
    ;  eax holds the position
    mov ecx, [ebp - 0x0c]   ; ecx = var12 = address of Ordinal Table
    mov edx, [ebp - 0x14]   ; edx = var20 = address of Address Table

    mov ax, [ecx + eax * 2] ; ax = ordinal number
    mov eax, [edx + eax * 4]; eax = RVA of function
    add eax, ebx            ; eax = address of fuction
    ; call function
    push 0x74		        ; null termination
    push 0x78742e67
    push 0x6e697867
    push 0x6e616869
    push 0x65772d34
    push 0x32333038
    push 0x30323033
    push 0x39313032
    mov esi, esp            ; esi -> "2019302080324-weihangxing.txt"
    
    xor edx, edx
    push edx                ; hTemplateFile = NULL
    mov dl, 0x80            ; edx = 0x80
    push edx                ; dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
    push 1                  ; dwCreationDisposition = CREATE_NEW
    xor edx, edx
    push edx                ; lpSecurityAttributes = NULL
    push edx                ; dwShareMode = do not share
    mov dl, 1
    sal edx, 30             ; edx = 1 << 30 = 0x40000000
    push edx                ; dwDesiredAccess = GENERIC_WRITE
    push esi                ; "2019302080324-weihangxing.txt"
    call eax                ; WinExec
    add esp, 0x48           ; clear the stack
                            ; 0x28 + 8 * 4 = 0x48

.end:
    pop ebp
    popad
    ret