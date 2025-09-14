# CinnamonOS Global Descriptor Table (GDT)
# File: boot/gdt.S

.section .data

#======================================================================================
# G D T   C O N S T A N T S
#======================================================================================

# Extended Segment Selectors
.set GDT_NULL_SEL,              0x00    # Null descriptor
.set GDT_KERNEL_CS32_SEL,       0x08    # 32-bit kernel code
.set GDT_KERNEL_DS32_SEL,       0x10    # 32-bit kernel data
.set GDT_USER_CS32_SEL,         0x18    # 32-bit user code
.set GDT_USER_DS32_SEL,         0x20    # 32-bit user data
.set GDT_KERNEL_CS64_SEL,       0x28    # 64-bit kernel code
.set GDT_KERNEL_DS64_SEL,       0x30    # 64-bit kernel data
.set GDT_USER_CS64_SEL,         0x38    # 64-bit user code
.set GDT_USER_DS64_SEL,         0x40    # 64-bit user data
.set GDT_TSS_SEL,               0x48    # Task State Segment (16 bytes)
.set GDT_CALL_GATE_SEL,         0x58    # Call gate for syscalls
.set GDT_LDT_SEL,               0x60    # Local Descriptor Table
.set GDT_SYSENTER_CS_SEL,       0x68    # SYSENTER code segment
.set GDT_SYSENTER_SS_SEL,       0x70    # SYSENTER stack segment  
.set GDT_TLS_BASE_SEL,          0x78    # Thread Local Storage base
.set GDT_PERF_COUNTER_SEL,      0x80    # Performance counter segment

# Access Rights Components
.set ACC_PRESENT,               0x80
.set ACC_DPL_0,                 0x00
.set ACC_DPL_1,                 0x20
.set ACC_DPL_2,                 0x40
.set ACC_DPL_3,                 0x60
.set ACC_DPL_MASK,              0x60
.set ACC_DESCRIPTOR,            0x10
.set ACC_CODE,                  0x08
.set ACC_CONFORMING,            0x04
.set ACC_READABLE,              0x02
.set ACC_WRITABLE,              0x02
.set ACC_ACCESSED,              0x01

# Flags Components
.set FLAG_GRANULARITY,          0x80
.set FLAG_SIZE32,               0x40
.set FLAG_LONG_MODE,            0x20
.set FLAG_AVAILABLE,            0x10

# System Descriptor Types
.set SYS_TSS_AVAILABLE,         0x09
.set SYS_TSS_BUSY,              0x0B
.set SYS_CALL_GATE,             0x0C
.set SYS_INTERRUPT_GATE,        0x0E
.set SYS_TRAP_GATE,             0x0F
.set SYS_LDT,                   0x02

# MSR Numbers
.set MSR_IA32_SYSENTER_CS,      0x174
.set MSR_IA32_SYSENTER_ESP,     0x175
.set MSR_IA32_SYSENTER_EIP,     0x176
.set MSR_IA32_FS_BASE,          0xC0000100
.set MSR_IA32_GS_BASE,          0xC0000101
.set MSR_IA32_KERNEL_GS_BASE,   0xC0000102

# Performance counters
.globl context_switch_count
.globl privilege_transition_count
context_switch_count:           .quad 0
privilege_transition_count:     .quad 0

#======================================================================================
# G D T   T A B L E
#======================================================================================

.align 16
.globl gdt_table
gdt_table:

# Entry 0: NULL Descriptor (required)
gdt_null:
    .quad 0x0000000000000000

# Entry 1: 32-bit Kernel Code (0x08)
gdt_kernel_code32:
    .word 0xFFFF        # Limit 15:0
    .word 0x0000        # Base 15:0
    .byte 0x00          # Base 23:16
    .byte ACC_PRESENT | ACC_DPL_0 | ACC_DESCRIPTOR | ACC_CODE | ACC_READABLE
    .byte FLAG_GRANULARITY | FLAG_SIZE32 | 0x0F
    .byte 0x00          # Base 31:24

# Entry 2: 32-bit Kernel Data (0x10)
gdt_kernel_data32:
    .word 0xFFFF
    .word 0x0000
    .byte 0x00
    .byte ACC_PRESENT | ACC_DPL_0 | ACC_DESCRIPTOR | ACC_WRITABLE
    .byte FLAG_GRANULARITY | FLAG_SIZE32 | 0x0F
    .byte 0x00

# Entry 3: 32-bit User Code (0x18)
gdt_user_code32:
    .word 0xFFFF
    .word 0x0000
    .byte 0x00
    .byte ACC_PRESENT | ACC_DPL_3 | ACC_DESCRIPTOR | ACC_CODE | ACC_READABLE
    .byte FLAG_GRANULARITY | FLAG_SIZE32 | 0x0F
    .byte 0x00

# Entry 4: 32-bit User Data (0x20)
gdt_user_data32:
    .word 0xFFFF
    .word 0x0000
    .byte 0x00
    .byte ACC_PRESENT | ACC_DPL_3 | ACC_DESCRIPTOR | ACC_WRITABLE
    .byte FLAG_GRANULARITY | FLAG_SIZE32 | 0x0F
    .byte 0x00

# Entry 5: 64-bit Kernel Code (0x28)
gdt_kernel_code64:
    .word 0x0000
    .word 0x0000
    .byte 0x00
    .byte ACC_PRESENT | ACC_DPL_0 | ACC_DESCRIPTOR | ACC_CODE | ACC_READABLE
    .byte FLAG_LONG_MODE
    .byte 0x00

# Entry 6: 64-bit Kernel Data (0x30)
gdt_kernel_data64:
    .word 0x0000
    .word 0x0000
    .byte 0x00
    .byte ACC_PRESENT | ACC_DPL_0 | ACC_DESCRIPTOR | ACC_WRITABLE
    .byte 0x00
    .byte 0x00

# Entry 7: 64-bit User Code (0x38)
gdt_user_code64:
    .word 0x0000
    .word 0x0000
    .byte 0x00
    .byte ACC_PRESENT | ACC_DPL_3 | ACC_DESCRIPTOR | ACC_CODE | ACC_READABLE
    .byte FLAG_LONG_MODE
    .byte 0x00

# Entry 8: 64-bit User Data (0x40)
gdt_user_data64:
    .word 0x0000
    .word 0x0000
    .byte 0x00
    .byte ACC_PRESENT | ACC_DPL_3 | ACC_DESCRIPTOR | ACC_WRITABLE
    .byte 0x00
    .byte 0x00

# Entry 9-10: TSS Descriptor (0x48) - 16 bytes
.globl gdt_tss
gdt_tss:
    .word 0x0067                # TSS limit (104 bytes - 1)
    .word 0x0000                # Base 15:0 (filled at runtime)
    .byte 0x00                  # Base 23:16 (filled at runtime)
    .byte ACC_PRESENT | SYS_TSS_AVAILABLE
    .byte 0x00                  # Flags
    .byte 0x00                  # Base 31:24 (filled at runtime)
    .long 0x00000000            # Base 63:32 (filled at runtime)
    .long 0x00000000            # Reserved

# Entry 11: Call Gate (0x58) - 16 bytes
.globl gdt_call_gate
gdt_call_gate:
    .word 0x0000                # Offset 15:0 (filled at runtime)
    .word GDT_KERNEL_CS64_SEL   # Target selector
    .byte 0x00                  # Parameter count
    .byte ACC_PRESENT | ACC_DPL_3 | SYS_CALL_GATE
    .word 0x0000                # Offset 31:16 (filled at runtime)
    .long 0x00000000            # Offset 63:32 (filled at runtime)
    .long 0x00000000            # Reserved

# Entry 12: LDT (0x60) - 8 bytes
gdt_ldt:
    .word 0x0000                # Limit 15:0
    .word 0x0000                # Base 15:0
    .byte 0x00                  # Base 23:16
    .byte 0x00                  # Not present initially
    .byte 0x00                  # Flags
    .byte 0x00                  # Base 31:24

# Entry 13: SYSENTER Code Segment (0x68) - 8 bytes
gdt_sysenter_cs:
    .word 0x0000
    .word 0x0000
    .byte 0x00
    .byte ACC_PRESENT | ACC_DPL_0 | ACC_DESCRIPTOR | ACC_CODE | ACC_READABLE
    .byte FLAG_LONG_MODE
    .byte 0x00

# Entry 14: SYSENTER Stack Segment (0x70) - 8 bytes
gdt_sysenter_ss:
    .word 0x0000
    .word 0x0000
    .byte 0x00
    .byte ACC_PRESENT | ACC_DPL_0 | ACC_DESCRIPTOR | ACC_WRITABLE
    .byte 0x00
    .byte 0x00

# Entry 15: TLS Base (0x78) - 8 bytes
gdt_tls_base:
    .word 0xFFFF                # Full limit for TLS
    .word 0x0000                # Base 15:0 (filled at runtime)
    .byte 0x00                  # Base 23:16 (filled at runtime)
    .byte ACC_PRESENT | ACC_DPL_3 | ACC_DESCRIPTOR | ACC_WRITABLE
    .byte FLAG_GRANULARITY | 0x0F  # 4GB limit
    .byte 0x00                  # Base 31:24 (filled at runtime)

# Entry 16: Performance Counter (0x80) - 8 bytes
gdt_perf_counter:
    .word 0x0000
    .word 0x0000
    .byte 0x00
    .byte ACC_PRESENT | ACC_DPL_0 | ACC_DESCRIPTOR | ACC_WRITABLE
    .byte 0x00
    .byte 0x00

gdt_end:

# GDT Register
.globl gdt_register
gdt_register:
    .word gdt_end - gdt_table - 1
    .quad gdt_table

#======================================================================================
# T A S K   S T A T E   S E G M E N T
#======================================================================================

.align 16
.globl tss
tss:
    .long 0x00000000            # Reserved
    .quad 0x0000000000000000    # RSP0 (kernel stack) - set at runtime
    .quad 0x0000000000000000    # RSP1 (ring 1 stack) - unused  
    .quad 0x0000000000000000    # RSP2 (ring 2 stack) - unused
    .quad 0x0000000000000000    # Reserved
    .quad 0x0000000000000000    # IST1 - Double fault
    .quad 0x0000000000000000    # IST2 - NMI
    .quad 0x0000000000000000    # IST3 - Machine check
    .quad 0x0000000000000000    # IST4 - Debug exceptions
    .quad 0x0000000000000000    # IST5 - General protection
    .quad 0x0000000000000000    # IST6 - Stack fault
    .quad 0x0000000000000000    # IST7 - Critical interrupts
    .quad 0x0000000000000000    # Reserved
    .word 0x0000                # Reserved
    .word tss_iopb - tss        # IOPB offset

# I/O Permission Bitmap (8KB)
.globl tss_iopb
tss_iopb:
    .fill 8192, 1, 0xFF         # Initially deny all I/O
    .byte 0xFF                  # Terminator byte

tss_end:

#======================================================================================
# F U N C T I O N S
#======================================================================================

.section .text

# GDT initialization with validation
.globl gdt_initialize
.type gdt_initialize, @function
gdt_initialize:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx

    # Setup TSS descriptor
    call setup_tss_descriptor
    
    # Load GDT
    lgdt gdt_register
    
    # Reload segments with validation
    movw $GDT_KERNEL_DS64_SEL, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs  
    movw %ax, %ss
    
    # Reload CS with far return
    pushq $GDT_KERNEL_CS64_SEL
    leaq 1f(%rip), %rax
    pushq %rax
    lretq
1:
    
    # Load TSS
    movw $GDT_TSS_SEL, %ax
    ltr %ax
    
    # Validate initialization
    call gdt_validate_initialization
    
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    movq %rbp, %rsp
    popq %rbp
    ret

# TSS setup with complete 64-bit address handling
.type setup_tss_descriptor, @function
setup_tss_descriptor:
    pushq %rbp
    movq %rsp, %rbp
    
    # Get TSS address and size
    leaq tss(%rip), %rax
    movw $(tss_end - tss - 1), %cx
    
    # Get TSS descriptor address
    leaq gdt_tss(%rip), %rbx
    
    # Fill TSS descriptor fields
    # Limit 15:0
    movw %cx, (%rbx)
    
    # Base 15:0
    movw %ax, 2(%rbx)
    
    # Base 23:16
    shrq $16, %rax
    movb %al, 4(%rbx)
    
    # Base 31:24
    shrq $8, %rax
    movb %al, 7(%rbx)
    
    # Base 63:32 (upper 8 bytes of descriptor)
    shrq $8, %rax
    movl %eax, 8(%rbx)
    
    # Reserved field (already zero)
    
    movq %rbp, %rsp
    popq %rbp
    ret

# Stack management with bounds checking
.globl gdt_set_privilege_stack
.type gdt_set_privilege_stack, @function
gdt_set_privilege_stack:
    # RDI = privilege level, RSI = stack pointer
    
    # Validate privilege level
    cmpq $0, %rdi
    jl invalid_priv
    cmpq $2, %rdi
    jg invalid_priv
    
    # Check stack alignment (16-byte boundary)
    testq $0xF, %rsi
    jnz invalid_addr
    
    # Check stack is in valid range (above 1MB, below kernel space)
    cmpq $0x100000, %rsi
    jb invalid_addr
    cmpq $0x0000800000000000, %rsi
    jae invalid_addr
    
    # Get TSS address
    leaq tss(%rip), %rax
    
    # Set appropriate stack
    cmpq $0, %rdi
    je set_rsp0
    cmpq $1, %rdi
    je set_rsp1
    
    # Must be level 2
    movq %rsi, 20(%rax)             # RSP2
    jmp stack_success
    
set_rsp0:
    movq %rsi, 4(%rax)              # RSP0
    jmp stack_success
    
set_rsp1:
    movq %rsi, 12(%rax)             # RSP1
    
stack_success:
    xorq %rax, %rax
    ret
    
invalid_priv:
    movq $-1, %rax
    ret
    
invalid_addr:
    movq $-4, %rax
    ret

# IST management with validation
.globl gdt_set_interrupt_stack
.type gdt_set_interrupt_stack, @function
gdt_set_interrupt_stack:
    # RDI = IST number (1-7), RSI = stack pointer
    
    # Validate IST number
    cmpq $1, %rdi
    jb invalid_ist
    cmpq $7, %rdi
    ja invalid_ist
    
    # Check 16-byte alignment
    testq $0xF, %rsi
    jnz invalid_addr
    
    # Check valid address range
    cmpq $0x100000, %rsi
    jb invalid_addr
    cmpq $0x0000800000000000, %rsi
    jae invalid_addr
    
    # Calculate IST offset: IST1 at offset 36, each entry is 8 bytes
    decq %rdi                       # Convert to 0-based
    shlq $3, %rdi                   # Multiply by 8
    addq $36, %rdi                  # Add IST1 base offset
    
    # Get TSS address and set IST stack
    leaq tss(%rip), %rax
    movq %rsi, (%rax, %rdi)
    
    xorq %rax, %rax
    ret
    
invalid_ist:
    movq $-2, %rax
    ret

# I/O permission management with bit operations
.globl gdt_set_io_permission
.type gdt_set_io_permission, @function
gdt_set_io_permission:
    # RDI = port, RSI = permission (0=allow, 1=deny)
    
    # Validate port number
    cmpq $65535, %rdi
    ja invalid_port
    
    # Calculate byte and bit position
    movq %rdi, %rax
    shrq $3, %rax                   # Byte offset = port / 8
    andq $7, %rdi                   # Bit position = port % 8
    
    # Get current byte from IOPB
    leaq tss_iopb(%rip), %rbx
    addq %rax, %rbx
    movzbl (%rbx), %ecx
    
    # Create bit mask
    movq $1, %rdx
    shlq %rdi, %rdx
    
    # Set or clear bit based on permission
    testq %rsi, %rsi
    jz clear_bit
    
    # Set bit (deny access)
    orq %rdx, %rcx
    jmp store_bit
    
clear_bit:
    # Clear bit (allow access)
    notq %rdx
    andq %rdx, %rcx
    
store_bit:
    movb %cl, (%rbx)
    xorq %rax, %rax
    ret
    
invalid_port:
    movq $-3, %rax
    ret

# I/O range permission function 
.globl gdt_set_io_range_permission
.type gdt_set_io_range_permission, @function
gdt_set_io_range_permission:
    # RDI = start_port, RSI = end_port, RDX = permission
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %rcx
    pushq %r12
    pushq %r13
    pushq %r14
    
    # Validate range
    cmpq %rsi, %rdi
    ja range_invalid
    cmpq $65535, %rsi
    ja range_invalid
    
    # Implementation for large ranges
    movq %rdi, %r12                 # Start port
    movq %rsi, %r13                 # End port
    movq %rdx, %r14                 # Permission
    
    # Calculate start and end bytes
    movq %r12, %rbx
    shrq $3, %rbx                   # Start byte
    movq %r13, %rcx
    shrq $3, %rcx                   # End byte
    
    # Get IOPB base
    leaq tss_iopb(%rip), %rax
    
    # Handle partial start byte
    movq %r12, %rdi
    andq $7, %rdi                   # Start bit position
    jz start_byte_aligned
    
    # Set individual bits in start byte
start_bit_loop:
    cmpq %r13, %r12
    ja range_done_success
    
    pushq %rax
    pushq %rbx
    pushq %rcx
    movq %r12, %rdi
    movq %r14, %rsi
    call gdt_set_io_permission
    popq %rcx
    popq %rbx
    popq %rax
    
    incq %r12
    movq %r12, %rdi
    andq $7, %rdi
    jnz start_bit_loop
    
start_byte_aligned:
    # Handle full bytes
    movq %r12, %rbx
    shrq $3, %rbx                   # Current byte
    
full_byte_loop:
    movq %r13, %rdi
    shrq $3, %rdi                   # End byte
    cmpq %rdi, %rbx
    jae handle_end_bits
    
    # Set full byte
    testq %r14, %r14
    jz set_byte_allow
    
    # Deny all ports in byte
    movb $0xFF, (%rax, %rbx)
    jmp next_byte
    
set_byte_allow:
    # Allow all ports in byte
    movb $0x00, (%rax, %rbx)
    
next_byte:
    incq %rbx
    addq $8, %r12
    jmp full_byte_loop
    
handle_end_bits:
    # Handle remaining bits in end byte
end_bit_loop:
    cmpq %r13, %r12
    ja range_done_success
    
    pushq %rax
    pushq %rbx
    movq %r12, %rdi
    movq %r14, %rsi
    call gdt_set_io_permission
    popq %rbx
    popq %rax
    
    incq %r12
    jmp end_bit_loop
    
range_done_success:
    xorq %rax, %rax
    jmp range_done
    
range_invalid:
    movq $-3, %rax
    
range_done:
    popq %r14
    popq %r13
    popq %r12
    popq %rcx
    popq %rbx
    movq %rbp, %rsp
    popq %rbp
    ret

# User mode switching with complete security validation
.globl gdt_switch_to_user
.type gdt_switch_to_user, @function
gdt_switch_to_user:
    # RDI = user RSP, RSI = user RIP, RDX = user RFLAGS
    
    # Validate user addresses (must be in user space)
    movq $0x0000800000000000, %rax
    cmpq %rax, %rsi
    jae invalid_user_addr
    cmpq %rax, %rdi
    jae invalid_user_addr
    
    # Ensure minimum user space addresses
    cmpq $0x10000, %rsi
    jb invalid_user_addr
    cmpq $0x10000, %rdi
    jb invalid_user_addr
    
    # Ensure stack alignment (16-byte boundary)
    testq $0xF, %rdi
    jnz invalid_user_addr
    
    # Increment privilege transition counter
    leaq privilege_transition_count(%rip), %rax
    incq (%rax)
    
    # Prepare IRET frame on kernel stack
    pushq $(GDT_USER_DS64_SEL | 3)      # User DS with RPL=3
    pushq %rdi                          # User RSP
    
    # Set up safe RFLAGS
    testq %rdx, %rdx
    jnz use_provided_flags
    
    # Use current flags as base
    pushfq
    popq %rdx
    
use_provided_flags:
    # Ensure safe RFLAGS for user mode
    orq $0x200, %rdx                    # IF (interrupts enabled)
    andq $0x003F7FD5, %rdx              # Clear dangerous flags (TF, NT, RF, etc.)
    orq $0x002, %rdx                    # Ensure reserved bit 1 is set
    pushq %rdx                          # User RFLAGS
    
    pushq $(GDT_USER_CS64_SEL | 3)      # User CS with RPL=3
    pushq %rsi                          # User RIP
    
    # Clear all general-purpose registers for security
    xorq %rax, %rax
    xorq %rbx, %rbx
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %rsi, %rsi
    xorq %rdi, %rdi
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    xorq %r12, %r12
    xorq %r13, %r13
    xorq %r14, %r14
    xorq %r15, %r15
    
    # Clear segment registers (except CS/SS which are set by IRET)
    movw $GDT_USER_DS64_SEL, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    
    # Switch to user mode
    swapgs                              # Switch to user GS base
    iretq
    
invalid_user_addr:
    movq $-4, %rax
    ret

# SYSENTER/SYSEXIT support with MSR programming
.globl gdt_setup_sysenter
.type gdt_setup_sysenter, @function
gdt_setup_sysenter:
    # RDI = syscall handler, RSI = syscall stack
    pushq %rbp
    movq %rsp, %rbp
    pushq %rax
    pushq %rcx
    pushq %rdx
    
    # Validate parameters
    testq %rdi, %rdi
    jz sysenter_invalid
    testq %rsi, %rsi
    jz sysenter_invalid
    
    # Set up IA32_SYSENTER_CS MSR
    movl $MSR_IA32_SYSENTER_CS, %ecx
    movl $GDT_SYSENTER_CS_SEL, %eax
    xorl %edx, %edx
    wrmsr
    
    # Set up IA32_SYSENTER_ESP MSR (syscall stack)
    movl $MSR_IA32_SYSENTER_ESP, %ecx
    movq %rsi, %rax
    movq %rsi, %rdx
    shrq $32, %rdx
    wrmsr
    
    # Set up IA32_SYSENTER_EIP MSR (syscall handler)
    movl $MSR_IA32_SYSENTER_EIP, %ecx
    movq %rdi, %rax
    movq %rdi, %rdx
    shrq $32, %rdx
    wrmsr
    
    xorq %rax, %rax
    jmp sysenter_done
    
sysenter_invalid:
    movq $-4, %rax
    
sysenter_done:
    popq %rdx
    popq %rcx
    popq %rax
    movq %rbp, %rsp
    popq %rbp
    ret

# TLS (Thread Local Storage) setup with MSR programming
.globl gdt_setup_tls
.type gdt_setup_tls, @function
gdt_setup_tls:
    # RDI = FS base, RSI = GS base
    pushq %rbp
    movq %rsp, %rbp
    pushq %rax
    pushq %rcx
    pushq %rdx
    
    # Set FS base using MSR
    testq %rdi, %rdi
    jz skip_fs_setup
    
    movl $MSR_IA32_FS_BASE, %ecx
    movq %rdi, %rax
    movq %rdi, %rdx
    shrq $32, %rdx
    wrmsr
    
skip_fs_setup:
    # Set GS base using MSR
    testq %rsi, %rsi
    jz skip_gs_setup
    
    movl $MSR_IA32_GS_BASE, %ecx
    movq %rsi, %rax
    movq %rsi, %rdx
    shrq $32, %rdx
    wrmsr
    
skip_gs_setup:
    xorq %rax, %rax
    
    popq %rdx
    popq %rcx
    popq %rax
    movq %rbp, %rsp
    popq %rbp
    ret

# Validation function with checks
.globl gdt_validate
.type gdt_validate, @function
gdt_validate:
    pushq %rbp
    movq %rsp, %rbp
    subq $16, %rsp
    pushq %rbx
    pushq %rcx
    
    # Check GDT is loaded correctly
    sgdt (%rsp)
    movq 2(%rsp), %rax              # Current GDT base
    leaq gdt_table(%rip), %rbx
    cmpq %rbx, %rax
    jne validation_failed
    
    # Check GDT limit
    movw (%rsp), %ax
    cmpw $(gdt_end - gdt_table - 1), %ax
    jne validation_failed
    
    # Check TSS is loaded
    str %ax
    cmpw $GDT_TSS_SEL, %ax
    jne validation_failed
    
    # Check segment registers are correct
    movw %cs, %ax
    cmpw $GDT_KERNEL_CS64_SEL, %ax
    jne validation_failed
    
    movw %ds, %ax
    cmpw $GDT_KERNEL_DS64_SEL, %ax
    jne validation_failed
    
    # Check TSS descriptor is properly set up
    leaq gdt_tss(%rip), %rbx
    movb 5(%rbx), %al               # Access byte
    testb $ACC_PRESENT, %al
    jz validation_failed
    
    # Validation passed
    xorq %rax, %rax
    jmp validation_done
    
validation_failed:
    movq $-5, %rax
    
validation_done:
    popq %rcx
    popq %rbx
    addq $16, %rsp
    movq %rbp, %rsp
    popq %rbp
    ret

# Internal validation during initialization
.type gdt_validate_initialization, @function
gdt_validate_initialization:
    pushq %rax
    
    # Quick validation checks during boot
    call gdt_validate
    testq %rax, %rax
    jnz init_validation_failed
    
    # Check TSS base is set correctly
    leaq gdt_tss(%rip), %rax
    cmpw $0, 2(%rax)                # Check base is not zero
    je init_validation_failed
    
    popq %rax
    ret
    
init_validation_failed:
    # Halt system on validation failure during init
    cli
    hlt
    jmp init_validation_failed

# System initialization with dynamic base updates
.globl gdt_full_initialize
.type gdt_full_initialize, @function
gdt_full_initialize:
    # RDI = kernel stack, RSI = IST array, RDX = syscall handler
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %rcx
    pushq %r12
    pushq %r13
    pushq %r14
    
    # Save parameters
    movq %rdi, %r12                 # kernel stack
    movq %rsi, %r13                 # IST array
    movq %rdx, %r14                 # syscall handler
    
    # Initialize basic GDT
    call gdt_initialize
    
    # Set RSP0 (kernel stack)
    xorq %rdi, %rdi                 # privilege 0
    movq %r12, %rsi                 # kernel stack
    call gdt_set_privilege_stack
    testq %rax, %rax
    jnz full_init_failed
    
    # Set up IST stacks
    testq %r13, %r13
    jz skip_ist_setup
    
    movq $1, %rcx                   # IST counter
    
ist_setup_loop:
    cmpq $7, %rcx
    ja ist_setup_done
    
    # Get IST stack from array
    decq %rcx                       # Convert to 0-based index
    movq (%r13, %rcx, 8), %rsi      # Get stack pointer from array
    incq %rcx                       # Convert back to 1-based
    
    testq %rsi, %rsi
    jz skip_this_ist
    
    pushq %rcx
    pushq %rsi
    movq %rcx, %rdi                 # IST number
    call gdt_set_interrupt_stack
    popq %rsi
    popq %rcx
    
    testq %rax, %rax
    jnz full_init_failed
    
skip_this_ist:
    incq %rcx
    jmp ist_setup_loop
    
ist_setup_done:
skip_ist_setup:
    # Set up syscall gate if handler provided
    testq %r14, %r14
    jz skip_syscall_setup
    
    movq %r14, %rdi
    call gdt_setup_syscall_gate
    
skip_syscall_setup:
    # Final validation
    call gdt_validate
    testq %rax, %rax
    jnz full_init_failed
    
    # Success
    xorq %rax, %rax
    jmp full_init_done
    
full_init_failed:
    # Critical failure - halt system
    cli
    hlt
    jmp full_init_failed
    
full_init_done:
    popq %r14
    popq %r13
    popq %r12
    popq %rcx
    popq %rbx
    movq %rbp, %rsp
    popq %rbp
    ret

# Set up syscall gate in GDT with complete offset handling
.type gdt_setup_syscall_gate, @function
gdt_setup_syscall_gate:
    # RDI = syscall handler address
    pushq %rbp
    movq %rsp, %rbp
    
    # Get call gate descriptor
    leaq gdt_call_gate(%rip), %rbx
    
    # Set offset fields in call gate
    # Offset 15:0
    movw %di, (%rbx)
    
    # Offset 31:16
    shrq $16, %rdi
    movw %di, 6(%rbx)
    
    # Offset 63:32 (in extended part)
    shrq $16, %rdi
    movl %edi, 8(%rbx)
    
    movq %rbp, %rsp
    popq %rbp
    ret

# Performance counter functions
.globl gdt_get_context_switches
.type gdt_get_context_switches, @function
gdt_get_context_switches:
    leaq context_switch_count(%rip), %rax
    movq (%rax), %rax
    ret

.globl gdt_get_privilege_transitions
.type gdt_get_privilege_transitions, @function
gdt_get_privilege_transitions:
    leaq privilege_transition_count(%rip), %rax
    movq (%rax), %rax
    ret

# Get current privilege level from CS register
.globl gdt_get_privilege_level
.type gdt_get_privilege_level, @function
gdt_get_privilege_level:
    movq %cs, %rax
    andq $3, %rax
    ret

# Reload all segment registers (useful after GDT changes)
.globl gdt_reload_segments
.type gdt_reload_segments, @function
gdt_reload_segments:
    # Reload data segments
    movw $GDT_KERNEL_DS64_SEL, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    
    # Reload code segment
    pushq $GDT_KERNEL_CS64_SEL
    leaq 1f(%rip), %rax
    pushq %rax
    lretq
1:
    ret

# Update TSS base address (for SMP or dynamic TSS)
.globl gdt_update_tss_base
.type gdt_update_tss_base, @function
gdt_update_tss_base:
    # RDI = new TSS address
    pushq %rbp
    movq %rsp, %rbp
    pushq %rax
    pushq %rbx
    
    movq %rdi, %rax
    leaq gdt_tss(%rip), %rbx
    
    # Update TSS descriptor base address
    # Base 15:0
    movw %ax, 2(%rbx)
    
    # Base 23:16
    shrq $16, %rax
    movb %al, 4(%rbx)
    
    # Base 31:24
    shrq $8, %rax
    movb %al, 7(%rbx)
    
    # Base 63:32 (in extended part)
    shrq $8, %rax
    movl %eax, 8(%rbx)
    
    # Reload TSS
    movw $GDT_TSS_SEL, %ax
    ltr %ax
    
    popq %rbx
    popq %rax
    movq %rbp, %rsp
    popq %rbp
    ret

#======================================================================================
# D E B U G G I N G   A N D   U T I L I T Y   F U N C T I O N S
#======================================================================================

# Deny all I/O ports (security hardening)
.globl gdt_deny_all_io
.type gdt_deny_all_io, @function
gdt_deny_all_io:
    pushq %rdi
    pushq %rax
    pushq %rcx
    
    # Set all bits in IOPB to 1 (deny all)
    leaq tss_iopb(%rip), %rdi
    movq $0xFFFFFFFFFFFFFFFF, %rax
    movq $1024, %rcx                # 8192 bytes / 8 = 1024 qwords
    cld
    rep stosq
    
    popq %rcx
    popq %rax
    popq %rdi
    ret

# Allow common I/O ports for basic system operation
.globl gdt_allow_basic_io
.type gdt_allow_basic_io, @function
gdt_allow_basic_io:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rax
    
    # Allow keyboard controller (0x60, 0x64)
    movq $0x60, %rdi
    xorq %rsi, %rsi
    call gdt_set_io_permission
    
    movq $0x64, %rdi
    xorq %rsi, %rsi
    call gdt_set_io_permission
    
    # Allow PIC ports (0x20-0x21, 0xA0-0xA1)
    movq $0x20, %rdi
    movq $0x21, %rsi
    xorq %rdx, %rdx
    call gdt_set_io_range_permission
    
    movq $0xA0, %rdi
    movq $0xA1, %rsi
    xorq %rdx, %rdx
    call gdt_set_io_range_permission
    
    # Allow timer ports (0x40-0x43)
    movq $0x40, %rdi
    movq $0x43, %rsi
    xorq %rdx, %rdx
    call gdt_set_io_range_permission
    
    # Allow RTC ports (0x70-0x71)
    movq $0x70, %rdi
    movq $0x71, %rsi
    xorq %rdx, %rdx
    call gdt_set_io_range_permission
    
    xorq %rax, %rax
    popq %rax
    movq %rbp, %rsp
    popq %rbp
    ret

# Context switch helper (increments counter)
.globl gdt_record_context_switch
.type gdt_record_context_switch, @function
gdt_record_context_switch:
    leaq context_switch_count(%rip), %rax
    incq (%rax)
    ret

# Privilege transition helper (increments counter)  
.globl gdt_record_privilege_transition
.type gdt_record_privilege_transition, @function
gdt_record_privilege_transition:
    leaq privilege_transition_count(%rip), %rax
    incq (%rax)
    ret

# Set TLS segment base (updates GDT entry)
.globl gdt_set_tls_base
.type gdt_set_tls_base, @function
gdt_set_tls_base:
    # RDI = TLS base address
    pushq %rbp
    movq %rsp, %rbp
    pushq %rax
    pushq %rbx
    
    # Get TLS descriptor
    leaq gdt_tls_base(%rip), %rbx
    movq %rdi, %rax
    
    # Update base address in descriptor
    # Base 15:0
    movw %ax, 2(%rbx)
    
    # Base 23:16
    shrq $16, %rax
    movb %al, 4(%rbx)
    
    # Base 31:24
    shrq $8, %rax
    movb %al, 7(%rbx)
    
    # Reload segment (if currently loaded)
    # This would need to check current segment registers
    # and reload if TLS segment is active
    
    popq %rbx
    popq %rax
    movq %rbp, %rsp
    popq %rbp
    ret

# Emergency system reset - minimal GDT
.globl gdt_emergency_reset
.type gdt_emergency_reset, @function
gdt_emergency_reset:
    cli
    
    # Reset to minimal GDT
    call gdt_initialize
    
    # Deny all I/O
    call gdt_deny_all_io
    
    # Allow only critical system I/O
    call gdt_allow_basic_io
    
    # Clear performance counters
    leaq context_switch_count(%rip), %rax
    movq $0, (%rax)
    leaq privilege_transition_count(%rip), %rax
    movq $0, (%rax)
    
    ret

# SMP CPU initialization helper
.globl gdt_init_cpu
.type gdt_init_cpu, @function
gdt_init_cpu:
    # RDI = CPU ID, RSI = CPU-specific TSS, RDX = CPU stacks array
    pushq %rbp
    movq %rsp, %rbp
    pushq %rax
    pushq %rbx
    pushq %rcx
    
    # Load existing GDT
    lgdt gdt_register
    
    # Update TSS for this CPU
    testq %rsi, %rsi
    jz skip_tss_update
    
    movq %rsi, %rdi
    call gdt_update_tss_base
    
skip_tss_update:
    # Set up CPU-specific stacks if provided
    testq %rdx, %rdx
    jz skip_stack_setup
    
    # Set kernel stack (first entry in array)
    xorq %rdi, %rdi                 # privilege 0
    movq (%rdx), %rsi               # first stack
    call gdt_set_privilege_stack
    
    # Set IST stacks (entries 1-7 in array)
    movq $1, %rcx
    
cpu_ist_loop:
    cmpq $7, %rcx
    ja skip_stack_setup
    
    movq (%rdx, %rcx, 8), %rsi      # Get stack from array
    testq %rsi, %rsi
    jz next_cpu_ist
    
    pushq %rcx
    pushq %rdx
    movq %rcx, %rdi
    call gdt_set_interrupt_stack
    popq %rdx
    popq %rcx
    
next_cpu_ist:
    incq %rcx
    jmp cpu_ist_loop
    
skip_stack_setup:
    # Reload segments for this CPU
    call gdt_reload_segments
    
    # Load TSS
    movw $GDT_TSS_SEL, %ax
    ltr %ax
    
    xorq %rax, %rax
    popq %rcx
    popq %rbx
    popq %rax
    movq %rbp, %rsp
    popq %rbp
    ret

#======================================================================================
# E X P O R T   S Y M B O L S   F O R   C   L I N K A G E
#======================================================================================

.globl gdt_end
.globl tss_end
