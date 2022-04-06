bits 32
%include "hldr32.inc"

;-----------------------------------------------------------------------------
;recover kernel32 image base
;-----------------------------------------------------------------------------

hldr_begin:
        pushad                                  ;must save ebx/edi/esi/ebp
        ; push eax, ecx, edx, ebx, original esp, ebp, esi, edi
        push    tebProcessEnvironmentBlock      ; 0x30
        pop     eax                             ; eax = 0x30
        fs mov  eax, dword [eax]                ; eax = address of PEB
        mov     eax, dword [eax + pebLdr]       ; eax = address of PEB_LDR_DATA
        mov     esi, dword [eax + ldrInLoadOrderModuleList]     ; eax = first entry of ldrInLoadOrderModuleList
        lodsd                                   ; eax = second entry, ntdll.dll
        xchg    eax, esi                        
        lodsd                                   ; eax = third entry, kernel32.dll
        mov     ebp, dword [eax + mlDllBase]    ; eax = kernel32.dll base address
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

        dd      0C97C1FFFh               ;GetProcAddress
        dd      03FC1BD8Dh               ;LoadLibraryA
        db      0

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

parse_exports:
        pop     esi                             ; esi = address of API CRC table
        mov     ebx, ebp                        ; ebx = base address of kernel32.dll
        mov     eax, dword [ebp + lfanew]       ; eax = RVA of PE signature
        add     ebx, dword [ebp + eax + IMAGE_DIRECTORY_ENTRY_EXPORT]   ; ebx = address of Export Table
        cdq                                     ; edx = 0, eax > 0

walk_names:
        mov     eax, ebp                        ; eax = base address of kernel32.dll
        mov     edi, ebp                        ; edi = base address of kernel32.dll
        inc     edx                             ; edx++
        add     eax, dword [ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNames]     ; eax = address of Name Pointer Table
        add     edi, dword [eax + edx * 4]      ; edi = edx'th function Name
        or      eax, -1                         ; eax = 0xffffffff

crc_outer:
        xor     al, byte [edi]                  ; al = ~byte [edi]
        push    8                               
        pop     ecx                             ; ecx = 8

crc_inner:
        shr     eax, 1                          ; eax >> 1
        jnc     crc_skip                        ; if eax[0] != 1
        xor     eax, 0edb88320h                 ; crc operation

crc_skip:
        loop    crc_inner
        inc     edi
        cmp     byte [edi], cl
        jne     crc_outer
        not     eax
        cmp     dword [esi], eax                ; compare API CRC
        jne     walk_names

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------
        ; found GetProcAddress
        ; edx = position of GetProcAddress
        mov     edi, ebp                ; edi = base address of kernel32.dll
        mov     eax, ebp                ; eax = base address of kernel32.dll
        add     edi, dword [ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNameOrdinals]      ; edi = address of Ordinal Table
        movzx   edi, word [edi + edx * 2]       ; edi = Orinal Number of GetProcAddress
        add     eax, dword [ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfFunctions] ; eax = address of Address Table
        mov     eax, dword [eax + edi * 4]      ; eax = RVA of GetProcAddress
        add     eax, ebp                        ; eax = address of GetProcAddress
        push    eax                             ; push address of GetProcAddress/LoadLibraryA
        lodsd
        sub     cl, byte [esi]
        jnz     walk_names

;-----------------------------------------------------------------------------
;save the pointers to the PE structure
;-----------------------------------------------------------------------------

        ; stack looks like:
        ; ImageBase, pushed by header code
        ; ret to header code    4 bytes
        ; pushad registers      0x20 bytes
        ; GetProcAddress        4 bytes
        ; LoadLibraryA          <== esp

        mov     esi, dword [esp + krncrcstk_size + 20h + 4]     ; esi = ImageBase
        mov     ebp, dword [esi + lfanew]       ; ebp = RVA of PE signature
        add     ebp, esi                        ; ebp = address of PE signature

        push    esi
        mov     ebx, esp                        ; ebx = address of ImageBase
        mov     edi, esi                        ; edi = ImageBase

;-----------------------------------------------------------------------------
;import DLL
;-----------------------------------------------------------------------------

        pushad
        mov     cl, IMAGE_DIRECTORY_ENTRY_IMPORT
        mov     ebp, dword [ecx + ebp]          ; ebp = RVA of Import Table
        test    ebp, ebp                        ; check if PE has import table
        je      import_popad                    ; if import table not found, skip loading
        add     ebp, edi                        ; ebp = address of Import Table

import_dll:
        mov     ecx, dword [ebp + _IMAGE_IMPORT_DESCRIPTOR.idName]      ; ecx = RVA of Import DLL Name
        jecxz   import_popad                                            ; jmp if ecx == 0
        add     ecx, dword [ebx]                                        ; ecx = address of Import DLL Name
        push    ecx                                                     ; address of Import DLL Name
        call    dword [ebx + mapstk_size + krncrcstk.kLoadLibraryA]     ; LoadLibraryA
        xchg    ecx, eax
        mov     edi, dword [ebp + _IMAGE_IMPORT_DESCRIPTOR.idFirstThunk]        ; edi = RVA of Import Address Table
        mov     esi, dword [ebp + _IMAGE_IMPORT_DESCRIPTOR.idOriginalFirstThunk]; esi = RVA of Import Name Table
        test    esi, esi                                                        ; if OriginalFirstThunk is NULL... 
        cmove   esi, edi                                                        ; use FirstThunk instead of OriginalFirstThunk
        add     esi, dword [ebx]                                                ; convert RVA to VA
        add     edi, dword [ebx]

import_thunks:
        lodsd                   ; eax = [esi], RVA of function name
        test    eax, eax
        je      import_next     ; reach 0x000000
        btr     eax, 31         
        jc      import_push
        add     eax, dword [ebx]; address of function Name
        inc     eax
        inc     eax

import_push:
        push    ecx             ; address of Import DLL Name, save ecx
        push    eax             ; address of function name
        push    ecx             ; address of Import DLL Name
        call    dword [ebx + mapstk_size + krncrcstk.kGetProcAddress]
        pop     ecx             ; restore ecx
        stosd                   ; store address of function to [edi]
        jmp     import_thunks

import_next:
        add     ebp, _IMAGE_IMPORT_DESCRIPTOR_size      ; turn to import next DLL functions
        jmp     import_dll

import_popad:
        popad

;-----------------------------------------------------------------------------
;apply relocations
;-----------------------------------------------------------------------------

        mov     cl, IMAGE_DIRECTORY_ENTRY_RELOCS
        lea     edx, dword [ebp + ecx]          ; relocation entry in data directory
        add     edi, dword [edx]                ; address of relocation block table
        xor     ecx, ecx

reloc_block:
        pushad
        mov     ecx, dword [edi + IMAGE_BASE_RELOCATION.reSizeOfBlock]  ; ecx = size of block
        sub     ecx, IMAGE_BASE_RELOCATION_size                         ; ecx = size of block - 8(meta info size)
        cdq                                                             ; edx = 0, because eax = 0

reloc_addr:
        movzx   eax, word [edi + edx + IMAGE_BASE_RELOCATION_size]      ; eax = firt reloc entry (16bits: 4 bits type, 12 bits offset)
        push    eax                                                     ; save reloc entry
        and     ah, 0f0h                                                ; get type of reloc entry
        cmp     ah, IMAGE_REL_BASED_HIGHLOW << 4                        ; if reloc type == HIGHLOW
        pop     eax                                                     ; restore reloc entry
        jne     reloc_abs                                               ; another type not HIGHLOW
        and     ah, 0fh                                                 ; get offset
        add     eax, dword [edi + IMAGE_BASE_RELOCATION.rePageRVA]      ; eax = RVA of reloc address
        add     eax, dword [ebx]                                        ; eax = address of reloc address
        mov     esi, dword [eax]                                        ; esi = old reloc address
        sub     esi, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohImageBasex]
        add     esi, dword [ebx]                                        ; new reloc address = old reloc address - old ImageBase + new ImageBase
        mov     dword [eax], esi                                        ; change reloc address
        xor     eax, eax                                                ; eax = 0

reloc_abs:
        test    eax, eax                                                ; check for IMAGE_REL_BASED_ABSOLUTE
        jne     hldr_exit                                               ; not supported relocation type
        inc     edx                                                     ; counter += 2
        inc     edx
        cmp     ecx, edx                                                ; reloc entry left
        jg     reloc_addr
        popad                                                           ; relocated a block
        add     ecx, dword [edi + IMAGE_BASE_RELOCATION.reSizeOfBlock]  ; ecx = current reloc block size
        add     edi, dword [edi + IMAGE_BASE_RELOCATION.reSizeOfBlock]  ; edi = next reloc position
        cmp     dword [edx + 4], ecx                                    ; if end of reloc block is reached
        jg     reloc_block

;-----------------------------------------------------------------------------
;call entrypoint
;
;to a DLL main:
;push 0
;push 1
;push dword [ebx]
;mov  eax, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohAddressOfEntryPoint]
;add  eax, dword [ebx]
;call eax
;
;to a RVA (an exported function's RVA, for example):
;
;mov  eax, 0xdeadf00d ; replace with addr
;add  eax, dword [ebx]
;call eax
;-----------------------------------------------------------------------------

        xor     ecx, ecx
        mov     eax, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohAddressOfEntryPoint]
        add     eax, dword [ebx]
        call    eax

;-----------------------------------------------------------------------------
;if fails or returns from host, restore stack and registers and return (somewhere)
;-----------------------------------------------------------------------------

hldr_exit:
        lea     esp, dword [ebx + mapstk_size + krncrcstk_size]
        popad
        ret     4 
hldr_end:

