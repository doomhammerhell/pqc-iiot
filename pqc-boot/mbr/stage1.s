; MBR Bootloader Stage 1 (NASM)
; Loads Stage 2 from sectors 1-64 to 0x7E00

[BITS 16]
[ORG 0x7C00]

start:
    ; 1. Setup Stack
    cli                     ; Disable interrupts
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00          ; Stack grows down from 0x7C00

    ; 2. Enable A20 Line (Fast method)
    in al, 0x92
    or al, 2
    out 0x92, al

    ; 3. Load Stage 2 from Disk (INT 13h)
    ; We assume Stage 2 is right after MBR (Sector 2)
    ; Load 32 sectors (16KB) to 0x7E00
    mov ah, 0x02            ; Read Sectors
    mov al, 32              ; Count
    mov ch, 0               ; Cylinder
    mov cl, 2               ; Sector (1-based, Sector 2)
    mov dh, 0               ; Head
    mov dl, 0x80            ; Drive (HDD 0)
    mov bx, 0x7E00          ; Buffer ES:BX
    int 0x13
    jc disk_error

    ; 4. Switch to Protected Mode
    lgdt [gdt_descriptor]
    mov eax, cr0
    or eax, 1               ; Set PE bit
    mov cr0, eax
    
    ; 5. Jump to 32-bit Code (Stage 2 Entry)
    jmp CODE_SEG:init_pm

[BITS 32]
init_pm:
    mov ax, DATA_SEG
    mov ds, ax
    mov ss, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    mov ebp, 0x90000        ; Set 32-bit stack
    mov esp, ebp

    ; Jump to Rust Entry Point (defined in linker script / main.rs)
    extern _start
    call _start
    
    hlt

disk_error:
    mov ah, 0x0E
    mov al, 'E'
    int 0x10
    hlt

; Global Descriptor Table
gdt_start:
    dd 0x0                  ; Null Descriptor
    dd 0x0

gdt_code: 
    dw 0xFFFF               ; Limit (0-15)
    dw 0x0                  ; Base (0-15)
    db 0x0                  ; Base (16-23)
    db 10011010b            ; Access (Present, Ring 0, Code, Exec/Read)
    db 11001111b            ; Granularity (4KB, 32-bit)
    db 0x0                  ; Base (24-31)

gdt_data:
    dw 0xFFFF
    dw 0x0
    db 0x0
    db 10010010b            ; Access (Present, Ring 0, Data, Read/Write)
    db 11001111b
    db 0x0

gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

CODE_SEG equ gdt_code - gdt_start
DATA_SEG equ gdt_data - gdt_start

times 510-($-$$) db 0
dw 0xAA55
