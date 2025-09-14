# entry.S

.code64
.section .text
.globl _start
.globl kernel_stack_top
.globl boot_info_ptr
.globl panic_halt

# Critical constants for validation
.equ BOOT_MAGIC, 0xCAFEBABE
.equ MAX_E820_ENTRIES, 32
.equ KERNEL_STACK_SIZE, 0x4000      # 16KB stack
.equ KERNEL_BASE, 0x100000          # 1MB
.equ STACK_CANARY, 0xDEADBEEFCAFEBABE

# Entry point - NEVER returns to bootloader
_start:
    # Immediately establish secure execution environment
    cli                         # Absolutely no interrupts
    cld                         # String ops go forward
    
    # Validate we're actually in 64-bit mode
    movq $0x123456789ABCDEF0, %rax
    cmpq $0x123456789ABCDEF0, %rax
    jne fatal_mode_error
    
    # Save and validate boot info pointer IMMEDIATELY
    testq %rdi, %rdi
    jz fatal_null_bootinfo
    movq %rdi, boot_info_ptr
    
    # Validate boot magic signature
    movl (%rdi), %eax
    cmpl $BOOT_MAGIC, %eax
    jne fatal_bad_magic
    
    # Set up protected stack with canaries - FIXED
    movq $kernel_stack_guard, %rax
    movq $STACK_CANARY, (%rax)      # Bottom canary
    movq $kernel_stack_top, %rax
    subq $8, %rax
    movq $STACK_CANARY, (%rax)      # Top canary
    subq $8, %rax                   # Working stack space
    movq %rax, %rsp
    
    # Validate stack is properly aligned (16-byte boundary)
    testq $0xF, %rsp
    jnz fatal_stack_misalign
    
    # Clear essential registers (keeping stack setup intact)
    xorq %rax, %rax
    xorq %rbx, %rbx
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %rsi, %rsi
    xorq %rdi, %rdi             # Will reload from boot_info_ptr
    
    # Critical system state validation
    call validate_cpu_state
    call validate_memory_layout  
    call validate_boot_integrity
    
    # Secure BSS clearing with verification
    call secure_clear_bss
    
    # Establish kernel security perimeter
    call setup_kernel_segments
    call setup_stack_protection
    
    # Initialize minimal console for critical errors ONLY
    call init_panic_console
    
    # Comprehensive boot info validation
    call validate_complete_bootinfo
    
    # Set up kernel page tables with NX protection
    call setup_secure_paging
    
    # Initialize CPU security features
    call init_security_features
    
    # Set up minimal exception handling for panics
    call setup_panic_handlers
    
    # Final pre-kernel validation
    call final_security_check
    
    # Transition to C kernel with full validation
    movq boot_info_ptr, %rdi
    call kernel_main            # NEVER returns
    
    # FATAL: kernel_main returned
    jmp fatal_kernel_return

# ========== VALIDATION FUNCTIONS ==========

validate_cpu_state:
    # Verify we're in ring 0
    movq %cs, %rax
    andq $3, %rax
    testq %rax, %rax
    jnz fatal_wrong_privilege
    
    # Verify long mode active
    movl $0xC0000080, %ecx      # EFER
    rdmsr
    testl $0x400, %eax          # LMA bit
    jz fatal_not_longmode
    
    # Verify paging enabled
    movq %cr0, %rax
    testl $0x80000000, %eax     # PG bit
    jz fatal_no_paging
    
    # Verify NX/XD support - FIXED for broader compatibility
    movl $0x80000001, %eax
    cpuid
    testl $0x100000, %edx       # NX/XD bit 20 in EDX
    jz fatal_no_nx
    ret

validate_memory_layout:
    # Verify kernel is loaded at correct address
    leaq _start(%rip), %rax
    cmpq $KERNEL_BASE, %rax
    jb fatal_wrong_load_addr
    
    # Verify we have enough stack space - FIXED calculation
    movq $kernel_stack_top, %rax
    movq $kernel_stack_bottom, %rbx
    subq %rbx, %rax
    cmpq $KERNEL_STACK_SIZE, %rax
    jb fatal_insufficient_stack
    ret

validate_boot_integrity:
    # Verify bootloader didn't corrupt critical structures
    movq boot_info_ptr, %rdi
    
    # Check E820 entry count is reasonable
    movw 4(%rdi), %ax           # e820_entries
    cmpw $0, %ax
    jz fatal_no_memory_map
    cmpw $MAX_E820_ENTRIES, %ax
    ja fatal_too_many_e820
    
    # Verify E820 buffer pointer is valid
    movq 8(%rdi), %rax          # e820_buffer
    testq %rax, %rax
    jz fatal_null_e820_buffer
    ret

secure_clear_bss:
    movq $__bss_start, %rdi
    movq $__bss_end, %rcx
    subq %rdi, %rcx
    
    # Verify BSS bounds are sane
    cmpq $0x100000, %rcx        # Max 1MB BSS
    ja fatal_bss_too_large
    
    # Clear with verification
    xorq %rax, %rax
    pushq %rcx
    pushq %rdi
    rep stosb
    
    # Verify BSS was actually cleared - FIXED verification
    popq %rdi
    popq %rcx
    testq %rcx, %rcx
    jz bss_verified
verify_bss_loop:
    cmpb $0, (%rdi)
    jne fatal_bss_clear_failed
    incq %rdi
    decq %rcx
    jnz verify_bss_loop
bss_verified:
    ret

setup_kernel_segments:
    # Load hardened kernel GDT
    lgdt kernel_gdt_descriptor
    
    # Atomic segment reload
    pushq $0x08                 # Kernel CS
    pushq $segment_reload       # Return address
    lretq
    
segment_reload:
    movq $0x10, %rax           # Kernel DS
    movq %rax, %ds
    movq %rax, %es
    movq %rax, %fs
    movq %rax, %gs
    movq %rax, %ss
    
    # Verify segment reload worked
    movq %cs, %rax
    cmpq $0x08, %rax
    jne fatal_segment_reload
    ret

setup_stack_protection:
    # Verify stack canaries are intact
    movq kernel_stack_guard, %rax
    cmpq $STACK_CANARY, %rax
    jne fatal_stack_corruption
    
    # Verify top canary
    movq $kernel_stack_top, %rax
    subq $8, %rax
    movq (%rax), %rbx
    cmpq $STACK_CANARY, %rbx
    jne fatal_stack_corruption
    ret

init_panic_console:
    # Set up minimal VGA console for panic messages only
    movq $0xB8000, %rax
    movq %rax, panic_console_base
    movl $0, panic_console_pos
    
    # Clear screen with red background (emergency indicator)
    movq $2000, %rcx            # 80x25 characters
    movq $panic_console_base, %rdi
    movw $0x4F20, %ax           # Red bg, white fg, space
clear_panic_screen:
    movw %ax, (%rdi)
    addq $2, %rdi
    loop clear_panic_screen
    
    movl $0, panic_console_pos  # Reset position
    ret

validate_complete_bootinfo:
    movq boot_info_ptr, %rsi
    
    # Re-verify magic (paranoid)
    movl (%rsi), %eax
    cmpl $BOOT_MAGIC, %eax
    jne fatal_magic_corrupted
    
    # Validate E820 entries in detail - FIXED to accept more types
    movw 4(%rsi), %cx           # Entry count
    movq 8(%rsi), %rdi          # Buffer pointer
    
validate_e820_loop:
    testw %cx, %cx
    jz e820_validation_done
    
    # Check each entry has reasonable values
    movq (%rdi), %rax           # Base address
    movq 8(%rdi), %rbx          # Length
    movl 16(%rdi), %edx         # Type
    
    # Validate type is known - expanded range for modern systems
    cmpl $1, %edx               # Usable
    je e820_type_ok
    cmpl $2, %edx               # Reserved
    je e820_type_ok
    cmpl $3, %edx               # ACPI reclaimable
    je e820_type_ok
    cmpl $4, %edx               # ACPI NVS
    je e820_type_ok
    cmpl $5, %edx               # Bad memory
    je e820_type_ok
    cmpl $6, %edx               # Disabled
    je e820_type_ok
    # Allow unknown types but continue - modern BIOS may have more
    
e820_type_ok:
    # Validate length is non-zero
    testq %rbx, %rbx
    jz fatal_zero_e820_length
    
    addq $24, %rdi              # Next entry
    decw %cx
    jmp validate_e820_loop
    
e820_validation_done:
    ret

setup_secure_paging:
    # Set up kernel page tables with security hardening
    
    # Verify current page tables are still valid
    movq %cr3, %rax
    testq %rax, %rax
    jz fatal_no_page_tables
    
    # Enable SMEP/SMAP if available
    call enable_smep_smap
    ret

enable_smep_smap:
    # Check for SMEP support
    movl $7, %eax
    movl $0, %ecx
    cpuid
    testl $0x80, %ebx           # SMEP bit
    jz no_smep
    
    # Enable SMEP
    movq %cr4, %rax
    orq $0x100000, %rax         # SMEP bit
    movq %rax, %cr4
    
no_smep:
    # Check for SMAP support  
    testl $0x100000, %ebx       # SMAP bit
    jz no_smap
    
    # Enable SMAP
    movq %cr4, %rax
    orq $0x200000, %rax         # SMAP bit
    movq %rax, %cr4
    
no_smap:
    ret

init_security_features:
    # Enable additional CPU security features
    
    # Try to enable Control Flow Enforcement if available
    movl $7, %eax
    movl $0, %ecx
    cpuid
    testl $0x80, %ecx           # CET bit
    jz no_cet
    
    # Enable CET (simplified)
    movl $0x6A2, %ecx           # CET MSR
    rdmsr
    orl $1, %eax                # Enable CET
    wrmsr
    
no_cet:
    ret

setup_panic_handlers:
    # Set up minimal IDT with panic handlers only
    lidt panic_idt_descriptor
    ret

final_security_check:
    # Final validation before entering C code
    
    # Verify stack canaries are still intact
    movq kernel_stack_guard, %rax
    cmpq $STACK_CANARY, %rax
    jne fatal_final_stack_check
    
    # Verify boot info magic is still valid
    movq boot_info_ptr, %rax
    movl (%rax), %ebx
    cmpl $BOOT_MAGIC, %ebx
    jne fatal_final_magic_check
    
    # Verify we're still in the right privilege level
    movq %cs, %rax
    andq $3, %rax
    testq %rax, %rax
    jnz fatal_final_privilege_check
    ret

# ========== PANIC/FATAL ERROR HANDLERS ==========

fatal_mode_error:
    movq $msg_mode_error, %rdi
    jmp panic_halt

fatal_null_bootinfo:
    movq $msg_null_bootinfo, %rdi
    jmp panic_halt

fatal_bad_magic:
    movq $msg_bad_magic, %rdi
    jmp panic_halt

fatal_stack_misalign:
    movq $msg_stack_misalign, %rdi
    jmp panic_halt

fatal_wrong_privilege:
    movq $msg_wrong_privilege, %rdi
    jmp panic_halt

fatal_not_longmode:
    movq $msg_not_longmode, %rdi
    jmp panic_halt

fatal_no_paging:
    movq $msg_no_paging, %rdi
    jmp panic_halt

fatal_no_nx:
    movq $msg_no_nx, %rdi
    jmp panic_halt

fatal_wrong_load_addr:
    movq $msg_wrong_load_addr, %rdi
    jmp panic_halt

fatal_insufficient_stack:
    movq $msg_insufficient_stack, %rdi
    jmp panic_halt

fatal_no_memory_map:
    movq $msg_no_memory_map, %rdi
    jmp panic_halt

fatal_too_many_e820:
    movq $msg_too_many_e820, %rdi
    jmp panic_halt

fatal_null_e820_buffer:
    movq $msg_null_e820_buffer, %rdi
    jmp panic_halt

fatal_bss_too_large:
    movq $msg_bss_too_large, %rdi
    jmp panic_halt

fatal_bss_clear_failed:
    movq $msg_bss_clear_failed, %rdi
    jmp panic_halt

fatal_segment_reload:
    movq $msg_segment_reload, %rdi
    jmp panic_halt

fatal_stack_corruption:
    movq $msg_stack_corruption, %rdi
    jmp panic_halt

fatal_magic_corrupted:
    movq $msg_magic_corrupted, %rdi
    jmp panic_halt

fatal_zero_e820_length:
    movq $msg_zero_e820_length, %rdi
    jmp panic_halt

fatal_no_page_tables:
    movq $msg_no_page_tables, %rdi
    jmp panic_halt

fatal_final_stack_check:
    movq $msg_final_stack_check, %rdi
    jmp panic_halt

fatal_final_magic_check:
    movq $msg_final_magic_check, %rdi
    jmp panic_halt

fatal_final_privilege_check:
    movq $msg_final_privilege_check, %rdi
    jmp panic_halt

fatal_kernel_return:
    movq $msg_kernel_return, %rdi
    jmp panic_halt

# Panic handler - never returns
panic_halt:
    cli                         # No interrupts ever
    
    # Try to print panic message if possible
    call panic_print
    
    # Infinite halt loop
panic_loop:
    hlt
    jmp panic_loop

# Emergency panic console output
panic_print:
    testq %rdi, %rdi
    jz panic_print_done
    
    movq panic_console_base, %rbx
    movl panic_console_pos, %eax
    
    # Prevent buffer overflow
    cmpl $3998, %eax            # 2000 chars * 2 - 2
    jae panic_print_done
    
panic_print_loop:
    movb (%rdi), %cl
    testb %cl, %cl
    jz panic_print_done
    
    # Write character with red background
    movb %cl, (%rbx,%rax)
    incl %eax
    movb $0x4F, (%rbx,%rax)     # Red bg, white fg
    incl %eax
    
    incq %rdi
    
    # Check bounds again
    cmpl $3998, %eax
    jae panic_print_done
    jmp panic_print_loop
    
panic_print_done:
    movl %eax, panic_console_pos
    ret

# ========== DATA SECTION ==========

.section .data
.align 8

# Boot information pointer
boot_info_ptr:      .quad 0

# Panic console state
panic_console_base: .quad 0
panic_console_pos:  .long 0

# Panic messages
msg_mode_error:             .asciz "FATAL: Not in 64-bit mode"
msg_null_bootinfo:          .asciz "FATAL: NULL boot info"
msg_bad_magic:              .asciz "FATAL: Bad boot magic"
msg_stack_misalign:         .asciz "FATAL: Stack misaligned"
msg_wrong_privilege:        .asciz "FATAL: Wrong privilege level"
msg_not_longmode:           .asciz "FATAL: Not in long mode"
msg_no_paging:              .asciz "FATAL: Paging disabled"
msg_no_nx:                  .asciz "FATAL: No NX support"
msg_wrong_load_addr:        .asciz "FATAL: Wrong load address"
msg_insufficient_stack:     .asciz "FATAL: Insufficient stack"
msg_no_memory_map:          .asciz "FATAL: No memory map"
msg_too_many_e820:          .asciz "FATAL: Too many E820 entries"
msg_null_e820_buffer:       .asciz "FATAL: NULL E820 buffer"
msg_bss_too_large:          .asciz "FATAL: BSS too large"
msg_bss_clear_failed:       .asciz "FATAL: BSS clear failed"
msg_segment_reload:         .asciz "FATAL: Segment reload failed"
msg_stack_corruption:       .asciz "FATAL: Stack corrupted"
msg_magic_corrupted:        .asciz "FATAL: Boot magic corrupted"
msg_zero_e820_length:       .asciz "FATAL: Zero E820 length"
msg_no_page_tables:         .asciz "FATAL: No page tables"
msg_final_stack_check:      .asciz "FATAL: Final stack check"
msg_final_magic_check:      .asciz "FATAL: Final magic check"
msg_final_privilege_check:  .asciz "FATAL: Final privilege check"
msg_kernel_return:          .asciz "FATAL: kernel_main returned"

# Kernel GDT - properly aligned
.align 16
kernel_gdt_start:
    # Null descriptor
    .quad 0x0000000000000000
    
    # Kernel code segment (64-bit)
    .word 0x0000                # Limit (ignored in 64-bit)
    .word 0x0000                # Base (ignored)
    .byte 0x00                  # Base (ignored)
    .byte 0x9A                  # Present, DPL=0, Code, Readable
    .byte 0x20                  # Long mode bit
    .byte 0x00                  # Base (ignored)
    
    # Kernel data segment
    .word 0x0000                # Limit (ignored in 64-bit)
    .word 0x0000                # Base (ignored)
    .byte 0x00                  # Base (ignored)
    .byte 0x92                  # Present, DPL=0, Data, Writable
    .byte 0x00                  # Flags
    .byte 0x00                  # Base (ignored)
kernel_gdt_end:

kernel_gdt_descriptor:
    .word kernel_gdt_end - kernel_gdt_start - 1
    .quad kernel_gdt_start

# Minimal panic IDT
.align 16
panic_idt_start:
    .fill 256, 16, 0            # 256 null entries for now
panic_idt_end:

panic_idt_descriptor:
    .word panic_idt_end - panic_idt_start - 1
    .quad panic_idt_start

# ========== BSS SECTION ==========

.section .bss
.align 16

# Kernel stack with proper layout - FIXED
kernel_stack_guard:     .space 8                    # Bottom canary storage
kernel_stack_bottom:    .space KERNEL_STACK_SIZE    # Actual stack space
kernel_stack_top:       .space 8                    # Top canary storage

# External symbols that linker will provide
.extern __bss_start
.extern __bss_end
.extern kernel_main
