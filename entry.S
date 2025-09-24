# arch/x86/entry.S - Kernel Entry Point for Cinnamon OS
# This file handles the transition from UEFI bootloader to kernel proper
# Called from boot/boot.c via jump_to_kernel()
# I am quite proud of this 

.code64
.section .text

# External symbols from kernel
.extern kernel_main          # C entry point in init/main.c
.extern early_idt_handler    # Early interrupt handler

# Global symbols exported to bootloader
.global jump_to_kernel
.global kernel_entry
.global early_stack_top

# Constants
.equ KERNEL_STACK_SIZE, 0x8000     # 32KB kernel stack
.equ PAGE_SIZE, 0x1000             # 4KB page size
.equ EFLAGS_IF, 0x200              # Interrupt flag

# Bootstrap stack for early kernel initialization
# This is used until the proper kernel heap and stacks are set up
.section .bss
.align 16
early_stack_bottom:
    .skip KERNEL_STACK_SIZE
early_stack_top:

# Temporary page tables for initial memory mapping
# These will be replaced by the full MM subsystem later
.align PAGE_SIZE
.global boot_pml4
boot_pml4:
    .skip PAGE_SIZE

.align PAGE_SIZE  
.global boot_pdpt
boot_pdpt:
    .skip PAGE_SIZE

.align PAGE_SIZE
.global boot_pd
boot_pd:
    .skip PAGE_SIZE

# Main kernel entry point called by bootloader
# Parameters:
#   RDI = kernel_entry_point (the address to jump to - should be kernel_entry)
#   RSI = BootInfo* pointer
.section .text
jump_to_kernel:
    # Disable interrupts immediately - we're in a critical transition
    cli
    
    # Clear direction flag for string operations
    cld
    
    # Validate parameters - basic sanity checks
    test %rdi, %rdi
    jz halt_system          # Null entry point = fatal error
    test %rsi, %rsi  
    jz halt_system          # Null boot info = fatal error
    
    # Save boot info pointer in a safe register
    mov %rsi, %r15          # R15 = BootInfo* (preserved across calls)
    
    # Set up temporary stack - MUST be 16-byte aligned for x86_64 ABI
    mov $early_stack_top, %rsp
    and $0xFFFFFFFFFFFFFFF0, %rsp   # Ensure 16-byte alignment
    
    # Clear the stack frame
    xor %rbp, %rbp
    
    # Clear other registers for clean state
    xor %rax, %rax
    xor %rbx, %rbx  
    xor %rcx, %rcx
    xor %rdx, %rdx
    # R15 contains boot_info, don't clear
    xor %r8, %r8
    xor %r9, %r9
    xor %r10, %r10
    xor %r11, %r11
    xor %r12, %r12
    xor %r13, %r13
    xor %r14, %r14
    
    # Jump to actual kernel entry point
    # RDI should contain the kernel entry address
    jmp *%rdi

# Actual kernel entry point - this is where the ELF entry point should point
.global kernel_entry
kernel_entry:
    # We're now in the kernel proper
    # R15 still contains BootInfo*
    # Interrupts are disabled
    # We have a basic stack
    # UEFI GDT is still active and sufficient
    
    # Set up minimal page tables for higher-half kernel
    call setup_initial_paging
    
    # Set up minimal IDT for early exception handling
    call setup_early_idt
    
    # Now we can safely call C code
    # Pass BootInfo* as first parameter (System V ABI)
    mov %r15, %rdi          # Move boot_info to RDI
    
    # Ensure stack is still aligned before C call
    and $0xFFFFFFFFFFFFFFF0, %rsp
    
    # Transfer control to C kernel initialization
    call kernel_main
    
    # If kernel_main returns, something went wrong
    jmp halt_system

# Set up initial identity mapping + higher half mapping
# This is minimal - just enough to get the kernel running
setup_initial_paging:
    # Clear page tables
    mov $boot_pml4, %rdi
    mov $PAGE_SIZE, %rcx
    xor %rax, %rax
    rep stosb
    
    mov $boot_pdpt, %rdi  
    mov $PAGE_SIZE, %rcx
    xor %rax, %rax
    rep stosb
    
    mov $boot_pd, %rdi
    mov $PAGE_SIZE, %rcx  
    xor %rax, %rax
    rep stosb
    
    # Set up PML4 entry 0 (identity mapping) and entry 256 (higher half)
    # Entry 0: 0x00000000_00000000 - 0x00000000_3FFFFFFF (identity)
    # Entry 256: 0xFFFFFF80_00000000 - 0xFFFFFF80_3FFFFFFF (higher half)
    
    mov $boot_pml4, %rax
    mov $boot_pdpt, %rbx
    or $0x3, %rbx           # Present + Writable
    mov %rbx, (%rax)        # PML4[0] = PDPT
    mov %rbx, 2048(%rax)    # PML4[256] = PDPT (higher half)
    
    # Set up PDPT entry 0 (covers first 1GB)
    mov $boot_pdpt, %rax
    mov $boot_pd, %rbx
    or $0x3, %rbx           # Present + Writable  
    mov %rbx, (%rax)        # PDPT[0] = PD
    
    # Set up PD entries (2MB pages for simplicity)
    # Map first 1GB as 2MB pages
    mov $boot_pd, %rax
    mov $0x83, %rbx         # Present + Writable + Page Size (2MB)
    mov $512, %rcx          # 512 entries * 2MB = 1GB
    
setup_pd_loop:
    mov %rbx, (%rax)
    add $0x200000, %rbx     # Next 2MB physical address
    add $8, %rax            # Next PD entry
    loop setup_pd_loop
    
    # Load new page tables
    mov $boot_pml4, %rax
    mov %rax, %cr3
    
    ret

# Set up minimal IDT for early exception handling
setup_early_idt:
    # Set up a basic IDT with 256 entries
    # For now, all exceptions point to early_idt_handler
    
    # Allocate space for IDT (256 * 16 bytes = 4096 bytes)
    sub $4096, %rsp
    mov %rsp, %rdi          # IDT base
    
    # Fill IDT with early exception handler
    mov $256, %rcx          # 256 entries
    mov $early_idt_handler, %rax
    
setup_idt_loop:
    # IDT Entry format (16 bytes):
    # Offset 15:0 (2 bytes)
    # Selector (2 bytes) - kernel code segment
    # IST + Reserved (1 byte)  
    # Type/Attributes (1 byte) - 0x8E = present, ring 0, interrupt gate
    # Offset 31:16 (2 bytes)
    # Offset 63:32 (4 bytes)
    # Reserved (4 bytes)
    
    mov %ax, (%rdi)         # Offset 15:0
    movw $0x08, 2(%rdi)     # Code segment selector (UEFI kernel CS)
    movb $0x00, 4(%rdi)     # IST = 0
    movb $0x8E, 5(%rdi)     # Type = interrupt gate, present, ring 0
    shr $16, %rax
    mov %ax, 6(%rdi)        # Offset 31:16
    shr $16, %rax
    mov %eax, 8(%rdi)       # Offset 63:32
    movl $0, 12(%rdi)       # Reserved
    
    add $16, %rdi           # Next IDT entry
    mov $early_idt_handler, %rax  # Restore handler address
    loop setup_idt_loop
    
    # Load IDT
    sub $6, %rsp            # Space for IDT descriptor
    movw $4095, (%rsp)      # IDT limit (4096 bytes - 1)
    sub $4096, %rsp         # Point to IDT base
    mov %rsp, %rax
    mov %rax, 2(%rsp)       # Store IDT base in descriptor
    add $4096, %rsp         # Point back to descriptor
    lidt (%rsp)             # Load IDT
    add $6, %rsp            # Clean up descriptor
    add $4096, %rsp         # Clean up IDT space
    
    ret

# System halt - used for unrecoverable errors
halt_system:
    cli                     # Ensure interrupts are disabled
    
    # Try to print some indication of failure if possible
    # This is a best-effort attempt - may not work depending on when we failed
    mov $0xB8000, %rdi      # VGA text buffer (may not be available)
    mov $0x4F45, %ax        # 'E' with red background, white foreground
    stosw
    mov $0x4F52, %ax        # 'R'  
    stosw
    mov $0x4F52, %ax        # 'R'
    stosw
    
halt_loop:
    hlt                     # Halt CPU
    pause                   # Hint that we're in a spin loop
    jmp halt_loop          # Loop forever if somehow resumed

# Early exception handler - minimal handler for bootstrap phase
early_idt_handler:
    # This is called for any exception/interrupt during early boot
    # Just halt - proper exception handling comes later
    
    cli                     # Disable interrupts
    
    # Try to indicate exception occurred
    mov $0xB8000, %rdi      # VGA buffer
    mov $0x4F49, %ax        # 'I' (Interrupt/Exception)
    stosw
    mov $0x4F52, %ax        # 'R' 
    stosw
    mov $0x4F51, %ax        # 'Q'
    stosw
    
    jmp halt_system

# Debug/info functions that can be called from C code
.global get_rsp
get_rsp:
    mov %rsp, %rax
    ret

.global get_rbp  
get_rbp:
    mov %rbp, %rax
    ret

# CPU feature detection
.global check_cpu_features
check_cpu_features:
    # Check if we have required CPU features
    # Returns 0 if OK, non-zero if missing critical features
    
    pushq %rbx              # CPUID clobbers RBX
    
    # Check for CPUID support
    pushfq
    pop %rax
    mov %rax, %rcx
    xor $0x200000, %eax     # Flip ID bit
    push %rax
    popfq
    pushfq  
    pop %rax
    xor %rcx, %rax
    test $0x200000, %eax
    jz cpu_features_fail    # No CPUID support
    
    # Check for required features
    mov $1, %eax
    cpuid
    
    # Check for SSE2 (bit 26 in EDX)
    test $0x4000000, %edx
    jz cpu_features_fail
    
    # Check for x86_64 support
    mov $0x80000001, %eax
    cpuid
    test $0x20000000, %edx  # Long mode bit
    jz cpu_features_fail
    
    # All checks passed
    xor %rax, %rax
    popq %rbx
    ret
    
cpu_features_fail:
    mov $1, %rax            # Return failure
    popq %rbx
    ret

# Memory barrier functions for synchronization
.global memory_barrier
memory_barrier:
    mfence
    ret

.global read_barrier
read_barrier:  
    lfence
    ret

.global write_barrier
write_barrier:
    sfence
    ret

# MSR (Model Specific Register) access functions
.global read_msr
read_msr:
    # RDI contains MSR number
    mov %rdi, %rcx
    rdmsr                   # Result in EDX:EAX
    shl $32, %rdx
    or %rdx, %rax           # Combine into RAX
    ret

.global write_msr
write_msr:
    # RDI = MSR number, RSI = value
    mov %rdi, %rcx
    mov %rsi, %rax
    mov %rsi, %rdx
    shr $32, %rdx
    wrmsr
    ret

# Control register access
.global read_cr0
read_cr0:
    mov %cr0, %rax
    ret

.global read_cr2  
read_cr2:
    mov %cr2, %rax
    ret

.global read_cr3
read_cr3:
    mov %cr3, %rax
    ret

.global read_cr4
read_cr4:
    mov %cr4, %rax
    ret

.global write_cr0
write_cr0:
    mov %rdi, %cr0
    ret

.global write_cr3
write_cr3:
    mov %rdi, %cr3
    ret

.global write_cr4  
write_cr4:
    mov %rdi, %cr4
    ret

# End of file
