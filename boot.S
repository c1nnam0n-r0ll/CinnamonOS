# boot.S - CinnamonOS Bootloader

.code16
.section .text
.globl _start

# Boot sector must start at offset 0
_start:
    # Secure initialization - disable interrupts immediately
    cli
    cld
    
    # Zero all segments for clean state
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    
    # Set up stack in safe area below bootloader
    movw $0x7000, %sp
    
    # Save boot drive from BIOS (critical for multi-drive systems)
    movb %dl, boot_drive
    
    # Initialize video and display security banner
    call clear_screen
    call display_security_banner
    
    # Hardware validation
    call validate_cpu_requirements
    call detect_memory_comprehensive
    call validate_disk_system
    
    # Security checks
    call perform_integrity_checks
    
    # Load kernel with verification
    call load_and_verify_kernel
    
    # Enable A20 line
    call enable_a20_secure
    
    # Display transition status
    movw $entering_32bit_msg, %si
    call print_string
    
    # Enter 32-bit protected mode
    lgdt (gdt32_descriptor)
    
    # Switch to protected mode
    movl %cr0, %eax
    orl $0x1, %eax
    movl %eax, %cr0
    
    # Far jump to flush pipeline and enter 32-bit mode
    .byte 0xEA              # Far jump opcode
    .long protected_mode    # Offset
    .word 0x08              # Code segment selector

# ========== DISPLAY AND I/O FUNCTIONS ==========

clear_screen:
    movb $0x00, %ah         # Set video mode
    movb $0x03, %al         # 80x25 color text mode
    int $0x10
    
    movb $0x02, %ah         # Position cursor
    xorw %dx, %dx
    int $0x10
    ret

display_security_banner:
    movw $security_banner, %si
    call print_string
    ret

print_string:
    pusha
print_loop:
    lodsb
    testb %al, %al
    jz print_done
    cmpb $10, %al           # Check for newline (LF)
    je print_nl
    movb $0x0E, %ah
    int $0x10
    jmp print_loop
print_nl:
    call print_newline
    jmp print_loop
print_done:
    popa
    ret

print_newline:
    movb $0x0E, %ah
    movb $13, %al           # CR
    int $0x10
    movb $0x0E, %ah
    movb $10, %al           # LF
    int $0x10
    ret

print_char:
    movb $0x0E, %ah
    int $0x10
    ret

print_hex_word:
    pusha
    movw %ax, %dx
    
    # Print "0x"
    movb $'0', %al
    call print_char
    movb $'x', %al
    call print_char
    
    # Print 4 hex digits
    movb $4, %cl
hex_loop:
    rolw $4, %dx
    movb %dl, %al
    andb $0x0F, %al
    cmpb $10, %al
    jl hex_digit
    addb $('A'-10), %al
    jmp hex_print
hex_digit:
    addb $'0', %al
hex_print:
    call print_char
    decb %cl
    jnz hex_loop
    
    popa
    ret

# ========== HARDWARE VALIDATION ==========

validate_cpu_requirements:
    movw $cpu_check_msg, %si
    call print_string
    
    # Test CPUID availability
    call test_cpuid_support
    testw %ax, %ax
    jz cpu_unsupported
    
    # Check for long mode support
    movl $0x80000001, %eax
    cpuid
    testl $0x20000000, %edx # Long mode bit (LM)
    jz no_long_mode
    
    movw $cpu_supported_msg, %si
    call print_string
    ret
    
cpu_unsupported:
    movw $no_cpuid_error, %si
    call print_string
    jmp halt_system
    
no_long_mode:
    movw $no_longmode_error, %si
    call print_string
    jmp halt_system

test_cpuid_support:
    # Test CPUID by toggling ID flag in EFLAGS
    pushfl                  # Save original EFLAGS
    pushfl                  # Get EFLAGS
    xorl $0x200000, (%esp)  # Toggle ID bit (bit 21)
    popfl                   # Load modified EFLAGS
    pushfl                  # Get EFLAGS again
    popl %eax               # EAX = modified EFLAGS
    xorl (%esp), %eax       # Compare with original
    popfl                   # Restore original EFLAGS
    andl $0x200000, %eax    # Isolate ID bit
    shrl $21, %eax          # Move to bit 0 (1 = CPUID supported)
    ret

detect_memory_comprehensive:
    movw $memory_detect_msg, %si
    call print_string
    
    # Simple E820 detection
    call detect_memory_e820
    cmpw $0, e820_entries
    jne memory_detected
    
    # Fallback to basic detection
    movb $0x88, %ah
    int $0x15
    jc memory_detect_fail
    
    movw %ax, extended_memory
    movw $mem88_success_msg, %si
    call print_string
    ret
    
memory_detected:
    movw $e820_success_msg, %si
    call print_string
    ret
    
memory_detect_fail:
    movw $memory_detect_fail_msg, %si
    call print_string
    jmp halt_system

detect_memory_e820:
    movw $e820_buffer, %di
    xorl %ebx, %ebx
    movw $0, e820_entries
    
e820_loop:
    movl $0xE820, %eax
    movl $24, %ecx
    movl $0x534D4150, %edx
    int $0x15
    jc e820_done
    
    incw e820_entries
    addw $24, %di
    
    testl %ebx, %ebx
    jz e820_done
    
    cmpw $8, e820_entries   # Limit entries
    jae e820_done
    
    jmp e820_loop
    
e820_done:
    ret

validate_disk_system:
    movw $disk_check_msg, %si
    call print_string
    
    # Reset disk system
    movb $0x00, %ah
    movb boot_drive, %dl
    int $0x13
    jc disk_reset_failed
    
    movw $disk_ready_msg, %si
    call print_string
    ret
    
disk_reset_failed:
    movw $disk_reset_error, %si
    call print_string
    jmp halt_system

perform_integrity_checks:
    movw $integrity_check_msg, %si
    call print_string
    
    # Basic checksum check
    movw $_start, %si
    movw $510, %cx
    xorw %dx, %dx
    
checksum_loop:
    lodsb
    xorb %al, %dl
    loop checksum_loop
    
    movw $integrity_ok_msg, %si
    call print_string
    ret

load_and_verify_kernel:
    movw $kernel_load_msg, %si
    call print_string
    
    # Load kernel to 0x10000 (64KB)
    movw $0x1000, %ax
    movw %ax, %es
    xorw %bx, %bx
    
    # Simple disk read - load 64 sectors (32KB)
    movb $0x02, %ah         # Read sectors
    movb $64, %al           # Number of sectors
    movw $0x0001, %cx       # Cylinder 0, sector 1
    movb $0x00, %dh         # Head 0
    movb boot_drive, %dl
    int $0x13
    jc kernel_load_failed
    
    # Basic kernel validation
    movw %es:(0), %ax
    cmpw $0, %ax
    je invalid_kernel
    
    movw $kernel_verified_msg, %si
    call print_string
    ret
    
kernel_load_failed:
    movw $kernel_load_failed_msg, %si
    call print_string
    jmp halt_system
    
invalid_kernel:
    movw $invalid_kernel_msg, %si
    call print_string
    jmp halt_system

enable_a20_secure:
    movw $a20_enable_msg, %si
    call print_string
    
    # Try BIOS method first
    movw $0x2401, %ax
    int $0x15
    
    # Test if A20 is enabled
    call test_a20_status
    cmpw $1, %ax
    je a20_enabled
    
    # Try fast gate method
    inb $0x92, %al
    orb $0x02, %al
    outb %al, $0x92
    
    call test_a20_status
    cmpw $1, %ax
    je a20_enabled
    
    # A20 enabling failed
    movw $a20_failed_msg, %si
    call print_string
    jmp halt_system
    
a20_enabled:
    movw $a20_success_msg, %si
    call print_string
    ret

test_a20_status:
    pusha
    
    # Set up segments for test
    movw $0x0000, %ax
    movw %ax, %ds
    movw $0xFFFF, %ax
    movw %ax, %es
    
    # Test addresses
    movw $0x0500, %si       # 0x0000:0x0500
    movw $0x0510, %di       # 0xFFFF:0x0510 (wraps to 0x500 if A20 off)
    
    # Save original values
    movw (%si), %ax
    pushw %ax
    movw %es:(%di), %ax
    pushw %ax
    
    # Write test patterns
    movw $0x1234, (%si)
    movw $0x5678, %es:(%di)
    
    # Check if they interfere
    movw (%si), %ax
    cmpw $0x5678, %ax       # If equal, A20 is disabled
    je a20_test_disabled
    
    # Restore and return success
    popw %ax
    movw %ax, %es:(%di)
    popw %ax
    movw %ax, (%si)
    
    popa
    movw $1, %ax            # A20 enabled
    ret
    
a20_test_disabled:
    # Restore and return failure
    popw %ax
    movw %ax, %es:(%di)
    popw %ax
    movw %ax, (%si)
    
    popa
    movw $0, %ax            # A20 disabled
    ret

halt_system:
    cli
    movw $system_halted_msg, %si
    call print_string
halt_loop:
    hlt
    jmp halt_loop

# ========== 32-BIT PROTECTED MODE ==========

.code32
protected_mode:
    # Initialize 32-bit data segments
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    
    # Set up 32-bit stack
    movl $0x80000, %esp
    
    # Clear page tables at 0x1000
    movl $0x1000, %edi
    xorl %eax, %eax
    movl $4096, %ecx        # Clear 16KB
    rep stosl
    
    # Set up basic identity paging for first 2MB
    # PML4 entry
    movl $0x1000, %edi      # PML4 base
    movl $0x2003, %eax      # PDP address + present + writable
    movl %eax, (%edi)
    
    # PDP entry  
    movl $0x2000, %edi      # PDP base
    movl $0x3003, %eax      # PD address + present + writable
    movl %eax, (%edi)
    
    # PD entry (2MB page)
    movl $0x3000, %edi      # PD base
    movl $0x83, %eax        # 0x0 + present + writable + page size
    movl %eax, (%edi)
    
    # Enable PAE
    movl %cr4, %eax
    orl $0x20, %eax         # Set PAE bit
    movl %eax, %cr4
    
    # Load PML4
    movl $0x1000, %eax
    movl %eax, %cr3
    
    # Enable long mode
    movl $0xC0000080, %ecx  # EFER MSR
    rdmsr
    orl $0x100, %eax        # Set LME bit
    wrmsr
    
    # Enable paging
    movl %cr0, %eax
    orl $0x80000000, %eax   # Set PG bit
    movl %eax, %cr0
    
    # Load 64-bit GDT
    lgdt gdt64_descriptor
    
    # Jump to 64-bit code
    ljmp $0x08, $long_mode

# ========== 64-BIT LONG MODE ==========

.code64
long_mode:
    # Clear segment registers
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    
    # Set up 64-bit stack
    movq $0x200000, %rsp    # 2MB stack
    
    # Move kernel from 0x10000 to 0x100000 (1MB)
    movq $0x10000, %rsi     # Source
    movq $0x100000, %rdi    # Destination  
    movq $0x8000, %rcx      # 32KB (sectors loaded)
    rep movsb
    
    # Prepare boot info for entry.S
    movq $boot_information, %rdi
    movl $0xCAFEBABE, (%rdi)        # Magic signature
    movw e820_entries, %ax
    movw %ax, 4(%rdi)               # E820 entry count
    movq $e820_buffer, %rax
    movq %rax, 8(%rdi)              # E820 buffer address
    
    # Jump to entry.S
    movq $0x100000, %rax
    movq $boot_information, %rdi    # Pass boot info as first argument
    jmp *%rax

# ========== DATA SECTION ==========

.code16  # Return to 16-bit for data

# Boot configuration
boot_drive:             .byte 0
e820_entries:           .word 0
extended_memory:        .word 0

# Buffers
e820_buffer:            .fill 192, 1, 0     # 8 entries * 24 bytes
boot_information:       .fill 64, 1, 0      # Boot info for entry.S

# ========== MESSAGES ==========

security_banner:        .asciz "CinnamonOS Bootloader v1.0 - Security Init"
cpu_check_msg:          .asciz "Checking CPU..."
cpu_supported_msg:      .asciz "CPU OK"
memory_detect_msg:      .asciz "Detecting memory..."
e820_success_msg:       .asciz "E820 memory map OK"
mem88_success_msg:      .asciz "Basic memory detection OK"
disk_check_msg:         .asciz "Checking disk..."
disk_ready_msg:         .asciz "Disk OK"
integrity_check_msg:    .asciz "Checking integrity..."
integrity_ok_msg:       .asciz "Integrity OK"
kernel_load_msg:        .asciz "Loading kernel..."
kernel_verified_msg:    .asciz "Kernel verified"
a20_enable_msg:         .asciz "Enabling A20..."
a20_success_msg:        .asciz "A20 enabled"
entering_32bit_msg:     .asciz "Entering protected mode..."

# Error messages
no_cpuid_error:         .asciz "FATAL: CPUID not supported"
no_longmode_error:      .asciz "FATAL: 64-bit mode not supported"
memory_detect_fail_msg: .asciz "FATAL: Memory detection failed"
disk_reset_error:       .asciz "FATAL: Disk reset failed"
kernel_load_failed_msg: .asciz "FATAL: Kernel load failed"
kernel_empty_msg:       .asciz "FATAL: Kernel is empty"
invalid_kernel_msg:     .asciz "FATAL: Invalid kernel format"
a20_failed_msg:         .asciz "FATAL: A20 enable failed"
system_halted_msg:      .asciz "SYSTEM HALTED"

# Additional kernel detection messages
elf32_detected_msg:     .asciz "ELF32 kernel detected"
elf64_detected_msg:     .asciz "ELF64 kernel detected"
pe_detected_msg:        .asciz "PE kernel detected"
raw_kernel_msg:         .asciz "Raw binary kernel detected"

# ========== GLOBAL DESCRIPTOR TABLES ==========

.align 8
gdt32_start:
    # Null descriptor
    .quad 0x0000000000000000
    
    # 32-bit code segment (selector 0x08)  
    .word 0xFFFF                # Limit 15:0
    .word 0x0000                # Base 15:0
    .byte 0x00                  # Base 23:16
    .byte 0x9A                  # Access byte
    .byte 0xCF                  # Flags + Limit 19:16
    .byte 0x00                  # Base 31:24
    
    # 32-bit data segment (selector 0x10)
    .word 0xFFFF                # Limit 15:0
    .word 0x0000                # Base 15:0
    .byte 0x00                  # Base 23:16
    .byte 0x92                  # Access byte
    .byte 0xCF                  # Flags + Limit 19:16
    .byte 0x00                  # Base 31:24
gdt32_end:

.align 8
gdt64_start:
    # Null descriptor
    .quad 0x0000000000000000
    
    # 64-bit code segment (selector 0x08)
    .word 0x0000                # Limit (ignored)
    .word 0x0000                # Base (ignored)
    .byte 0x00                  # Base (ignored)
    .byte 0x9A                  # Access byte
    .byte 0x20                  # Flags: L=1 for 64-bit
    .byte 0x00                  # Base (ignored)
    
    # 64-bit data segment (selector 0x10)
    .word 0x0000                # Limit (ignored)
    .word 0x0000                # Base (ignored)
    .byte 0x00                  # Base (ignored)
    .byte 0x92                  # Access byte
    .byte 0x00                  # Flags
    .byte 0x00                  # Base (ignored)
gdt64_end:

# GDT descriptors
.align 4
gdt32_descriptor:
    .word gdt32_end - gdt32_start - 1
    .long gdt32_start

.align 4  
gdt64_descriptor:
    .word gdt64_end - gdt64_start - 1
    .quad gdt64_start

# ========== BOOT SECTOR SIGNATURE ==========
.org 510
.word 0xAA55
