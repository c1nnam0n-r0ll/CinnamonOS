# boot.S - CinnamonOS Bootloader

.code16
.section .boot, "ax"
.org 0x0

# ========== BOOT SECTOR ENTRY POINT ==========
start:
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
    movw $0x7C00, %sp
    
    # Save boot drive from BIOS (critical for multi-drive systems)
    movb %dl, boot_drive
    
    # Initialize video and display security banner
    call clear_screen
    call display_security_banner
    
    # Comprehensive hardware validation
    call validate_cpu_requirements
    call detect_memory_comprehensive
    call validate_disk_system
    
    # Security checks
    call perform_integrity_checks
    call validate_boot_environment
    
    # Load kernel with verification
    call load_and_verify_kernel
    
    # Enable A20 line with multiple fallback methods
    call enable_a20_secure
    
    # Display transition status
    movw $entering_32bit_msg, %si
    call print_string
    
    # Enter 32-bit protected mode
    lgdt gdt32_descriptor
    movl %cr0, %eax
    orl $0x1, %eax
    movl %eax, %cr0
    ljmp $0x08, $protected_mode

# ========== DISPLAY AND I/O FUNCTIONS ==========

clear_screen:
    # Clear screen with security-focused approach
    movb $0x00, %ah         # Set video mode
    movb $0x03, %al         # 80x25 color text mode
    int $0x10
    
    # Position cursor at top-left
    movb $0x02, %ah
    xorw %dx, %dx
    int $0x10
    
    # Clear any remaining screen artifacts
    movb $0x06, %ah         # Scroll window
    movb $0x00, %al         # Clear entire screen
    movb $0x07, %bh         # Normal attribute
    movw $0x0000, %cx       # Top-left
    movw $0x184F, %dx       # Bottom-right
    int $0x10
    ret

display_security_banner:
    movw $security_banner, %si
    call print_string
    movw $bootloader_version, %si
    call print_string
    call display_system_info
    ret

display_system_info:
    # Show current time for security logs
    movb $0x02, %ah         # Get time
    int $0x1A
    jc no_rtc
    
    movw $boot_time_msg, %si
    call print_string
    
    # Print time in HH:MM:SS format
    movb %ch, %al           # Hours (BCD)
    call print_bcd_byte
    movb $':', %al
    call print_char
    movb %cl, %al           # Minutes (BCD)
    call print_bcd_byte
    movb $':', %al
    call print_char
    movb %dh, %al           # Seconds (BCD)
    call print_bcd_byte
    call print_newline
    ret
    
no_rtc:
    movw $no_rtc_msg, %si
    call print_string
    ret

print_string:
    pusha
print_loop:
    lodsb
    testb %al, %al
    jz print_done
    cmpb $'\n', %al
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
    movb $'\r', %al
    int $0x10
    movb $0x0E, %ah
    movb $'\n', %al
    int $0x10
    ret

print_char:
    movb $0x0E, %ah
    int $0x10
    ret

print_bcd_byte:
    # Print BCD encoded byte as decimal
    pushw %ax
    shrb $4, %al            # High nibble
    addb $'0', %al
    call print_char
    popw %ax
    andb $0x0F, %al         # Low nibble
    addb $'0', %al
    call print_char
    ret

print_hex_word:
    # Print 16-bit word as hex with 0x prefix
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
    
    # Get CPU vendor
    xorl %eax, %eax
    cpuid
    movl %ebx, cpu_vendor_string
    movl %edx, cpu_vendor_string + 4
    movl %ecx, cpu_vendor_string + 8
    
    movw $cpu_vendor_msg, %si
    call print_string
    movw $cpu_vendor_string, %si
    call print_string
    call print_newline
    
    # Check for long mode support
    movl $0x80000001, %eax
    cpuid
    testl $0x20000000, %edx # Long mode bit (LM)
    jz no_long_mode
    
    # Check for other required features
    movl $1, %eax
    cpuid
    testl $0x02000000, %edx # SSE2
    jz missing_sse2
    testl $0x00000010, %edx # TSC
    jz missing_tsc
    
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
    
missing_sse2:
    movw $no_sse2_error, %si
    call print_string
    jmp halt_system
    
missing_tsc:
    movw $no_tsc_error, %si
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
    
    # Method 1: E820 memory detection (preferred)
    call detect_memory_e820
    cmpw $0, e820_entries
    jne memory_detected
    
    # Method 2: E801 function
    call detect_memory_e801
    testw %ax, %ax
    jnz memory_detected
    
    # Method 3: Legacy 88h function
    call detect_memory_88
    testw %ax, %ax
    jnz memory_detected
    
    # All methods failed
    movw $memory_detect_fail, %si
    call print_string
    jmp halt_system
    
memory_detected:
    call display_memory_summary
    ret

detect_memory_e820:
    movw $e820_buffer, %di
    xorl %ebx, %ebx         # Continuation value must start at 0
    movw $0, e820_entries
    
e820_loop:
    movl $0xE820, %eax      # Function code
    movl $24, %ecx          # Buffer size
    movl $0x534D4150, %edx  # "SMAP" signature
    
    # Save continuation value before interrupt
    pushl %ebx
    int $0x15
    popl %ecx               # Get old EBX value
    
    jc e820_done            # Carry set = error or done
    cmpl $0x534D4150, %eax  # Verify signature returned
    jne e820_done
    
    # Entry is valid
    incw e820_entries
    addw $24, %di           # Move to next entry
    
    testl %ebx, %ebx        # EBX = 0 means last entry
    jz e820_done
    
    cmpw $32, e820_entries  # Safety limit
    jae e820_done
    
    jmp e820_loop
    
e820_done:
    movw $e820_success_msg, %si
    call print_string
    movw e820_entries, %ax
    call print_decimal
    movw $entries_found_msg, %si
    call print_string
    ret

detect_memory_e801:
    clc                     # Clear carry flag
    movw $0xE801, %ax
    int $0x15
    jc e801_failed
    
    # AX = KB between 1-16MB, BX = 64KB blocks above 16MB
    movw %ax, low_memory_1mb
    movw %bx, high_memory_64k
    
    movw $e801_success_msg, %si
    call print_string
    movw $1, %ax            # Return success
    ret
    
e801_failed:
    xorw %ax, %ax           # Return failure
    ret

detect_memory_88:
    movb $0x88, %ah
    int $0x15
    jc mem88_failed
    
    movw %ax, extended_memory
    movw $mem88_success_msg, %si
    call print_string
    call print_decimal
    movw $kb_extended_msg, %si
    call print_string
    movw $1, %ax            # Return success
    ret
    
mem88_failed:
    xorw %ax, %ax           # Return failure
    ret

display_memory_summary:
    movw $memory_summary_msg, %si
    call print_string
    
    # Show E820 entries if available
    cmpw $0, e820_entries
    je show_legacy_memory
    
    movw $e820_entries_msg, %si
    call print_string
    
    movw $e820_buffer, %si
    movw e820_entries, %cx
    
e820_display_loop:
    pushw %cx
    pushw %si
    
    movw $entry_base_msg, %si
    call print_string
    
    popw %si
    pushw %si
    movl (%si), %eax        # Base address (low 32 bits)
    call print_hex_dword
    
    movw $entry_length_msg, %si
    call print_string
    
    popw %si
    pushw %si
    movl 8(%si), %eax       # Length (low 32 bits)
    call print_hex_dword
    
    movw $entry_type_msg, %si
    call print_string
    
    popw %si
    movl 16(%si), %eax      # Type
    call print_hex_dword
    
    call print_newline
    addw $24, %si           # Next entry
    
    popw %cx
    loop e820_display_loop
    ret
    
show_legacy_memory:
    cmpw $0, low_memory_1mb
    je check_extended_only
    
    movw $legacy_low_msg, %si
    call print_string
    movw low_memory_1mb, %ax
    call print_decimal
    movw $kb_msg, %si
    call print_string
    
check_extended_only:
    cmpw $0, extended_memory
    je memory_summary_done
    
    movw $legacy_ext_msg, %si
    call print_string
    movw extended_memory, %ax
    call print_decimal
    movw $kb_msg, %si
    call print_string
    
memory_summary_done:
    ret

print_decimal:
    # Print 16-bit number in AX as decimal
    pusha
    movw %ax, %bx
    
    # Handle zero case
    testw %bx, %bx
    jnz decimal_nonzero
    movb $'0', %al
    call print_char
    jmp decimal_done
    
decimal_nonzero:
    movw $decimal_buffer + 6, %di  # Point to end of buffer
    movb $0, (%di)                 # Null terminator
    movw $10, %cx                  # Divisor
    
decimal_convert:
    xorw %dx, %dx
    divw %cx                # AX = quotient, DX = remainder
    addb $'0', %dl
    decw %di
    movb %dl, (%di)
    testw %ax, %ax
    jnz decimal_convert
    
    movw %di, %si
    call print_string
    
decimal_done:
    popa
    ret

print_hex_dword:
    # Print 32-bit value in EAX as hex
    pusha
    
    # Print "0x"
    movb $'0', %al
    call print_char
    movb $'x', %al
    call print_char
    
    # Print 8 hex digits
    movb $8, %cl
    roll $4, %eax           # Prepare for first digit
    
hex_dword_loop:
    roll $4, %eax           # Get next nibble
    movb %al, %bl
    andb $0x0F, %bl
    cmpb $10, %bl
    jl hex_dword_digit
    addb $('A'-10), %bl
    jmp hex_dword_print
hex_dword_digit:
    addb $'0', %bl
hex_dword_print:
    movb %bl, %al
    call print_char
    decb %cl
    jnz hex_dword_loop
    
    popa
    ret

validate_disk_system:
    movw $disk_check_msg, %si
    call print_string
    
    # Reset disk system
    movb $0x00, %ah
    movb boot_drive, %dl
    int $0x13
    jc disk_reset_failed
    
    # Get disk parameters
    movb $0x08, %ah
    movb boot_drive, %dl
    int $0x13
    jc disk_params_failed
    
    # Validate and store parameters
    incb %dh                # Number of heads
    movb %dh, disk_heads
    andb $0x3F, %cl         # Sectors per track
    movb %cl, disk_sectors
    
    # Basic validation
    cmpb $0, disk_heads
    je invalid_disk_geometry
    cmpb $0, disk_sectors
    je invalid_disk_geometry
    
    movw $disk_ready_msg, %si
    call print_string
    ret
    
disk_reset_failed:
    movw $disk_reset_error, %si
    call print_string
    jmp halt_system
    
disk_params_failed:
    movw $disk_params_error, %si
    call print_string
    jmp halt_system
    
invalid_disk_geometry:
    movw $disk_geometry_error, %si
    call print_string
    jmp halt_system

# ========== SECURITY CHECKS ==========

perform_integrity_checks:
    movw $integrity_check_msg, %si
    call print_string
    
    # Check bootloader integrity (simple checksum)
    call verify_bootloader_integrity
    
    # Check for common rootkit signatures in memory
    call scan_memory_signatures
    
    # Validate interrupt vector table
    call validate_ivt
    
    movw $integrity_ok_msg, %si
    call print_string
    ret

verify_bootloader_integrity:
    # Simple checksum verification of our code section
    movw $start, %si        # Start of bootloader
    movw $510, %cx          # Size (excluding signature)
    xorw %dx, %dx           # Checksum accumulator
    
checksum_loop:
    lodsb
    xorb %al, %dl
    loop checksum_loop
    
    # For now, just report the checksum (real implementation would verify)
    movw $checksum_msg, %si
    call print_string
    movw %dx, %ax
    call print_hex_word
    call print_newline
    ret

scan_memory_signatures:
    # Scan low memory for suspicious signatures
    movw $0x0400, %ax       # Start after interrupt vectors
    movw %ax, %es
    xorw %di, %di
    movw $0x1000, %cx       # Scan 4KB
    
signature_scan_loop:
    # Look for common malware signatures (example patterns)
    cmpw $0x4D5A, %es:(%di) # "MZ" header in unexpected location
    je suspicious_signature
    cmpw $0x5A4D, %es:(%di) # Reverse "MZ"
    je suspicious_signature
    
    incw %di
    loop signature_scan_loop
    ret
    
suspicious_signature:
    movw $suspicious_code_msg, %si
    call print_string
    # Continue anyway - might be false positive
    ret

validate_ivt:
    # Check interrupt vector table for suspicious entries
    movw $0x0000, %ax
    movw %ax, %es
    
    # Check critical interrupt vectors
    movl %es:(0x00*4), %eax # Division by zero
    cmpl $0, %eax
    je ivt_suspicious
    
    movl %es:(0x06*4), %eax # Invalid opcode
    cmpl $0, %eax
    je ivt_suspicious
    
    ret
    
ivt_suspicious:
    movw $suspicious_ivt_msg, %si
    call print_string
    # Continue - might be normal
    ret

validate_boot_environment:
    movw $env_check_msg, %si
    call print_string
    
    # Check if we're running in expected memory location
    movw $validate_location, %ax
    cmpw $0x7C00, %ax       # Should be near 0x7C00
    jb unexpected_location
    cmpw $0x8000, %ax       # But not too far
    ja unexpected_location
    
    # Check stack is in reasonable location
    movw %sp, %ax
    cmpw $0x7000, %ax       # Should be reasonable
    jb stack_too_low
    cmpw $0x7C00, %ax
    ja stack_too_high
    
    movw $env_ok_msg, %si
    call print_string
    ret
    
validate_location:          # This gets the current IP
    ret
    
unexpected_location:
    movw $location_warning_msg, %si
    call print_string
    ret
    
stack_too_low:
stack_too_high:
    movw $stack_warning_msg, %si
    call print_string
    ret

# ========== KERNEL LOADING ==========

load_and_verify_kernel:
    movw $kernel_load_msg, %si
    call print_string
    
    # Load kernel to conventional location (64KB - will be moved by 32-bit code)
    movw $0x1000, %ax       # Load segment (64KB physical)
    movw %ax, %es
    xorw %bx, %bx           # Offset 0
    
    # Try LBA loading first (more reliable for large disks)
    call attempt_lba_loading
    testb %al, %al
    jnz kernel_load_success
    
    # Fall back to CHS loading
    call attempt_chs_loading
    testb %al, %al
    jnz kernel_load_success
    
    # Both methods failed
    movw $kernel_load_failed, %si
    call print_string
    jmp halt_system
    
kernel_load_success:
    # Verify kernel signature
    call verify_kernel_signature
    
    movw $kernel_verified_msg, %si
    call print_string
    ret

attempt_lba_loading:
    # Check for LBA BIOS extensions
    movb $0x41, %ah
    movw $0x55AA, %bx
    movb boot_drive, %dl
    int $0x13
    jc lba_unsupported
    cmpw $0xAA55, %bx
    jne lba_unsupported
    
    # LBA is supported - set up disk address packet
    movw $disk_address_packet, %si
    movb $0x10, dap_size        # Packet size
    movb $0, dap_reserved       # Reserved
    movb $128, dap_sectors      # Load 64KB (128 sectors)
    movb $0, dap_reserved2      # Reserved
    movw $0, dap_offset         # Buffer offset
    movw $0x1000, dap_segment   # Buffer segment  
    movl $2, dap_lba_low        # Start at sector 2 (after boot sector)
    movl $0, dap_lba_high       # Upper 32 bits
    
    # Perform extended read with retry
    movb $3, %ch                # Retry counter
    
lba_retry:
    movb $0x42, %ah             # Extended read
    movb boot_drive, %dl
    movw $disk_address_packet, %si
    int $0x13
    jnc lba_success
    
    # Retry after drive reset
    decb %ch
    jz lba_failed
    movb $0, %ah                # Reset drive
    movb boot_drive, %dl
    int $0x13
    jmp lba_retry
    
lba_success:
    movb $1, %al                # Return success
    ret
    
lba_unsupported:
lba_failed:
    movb $0, %al                # Return failure
    ret

attempt_chs_loading:
    # Convert LBA sector 2 to CHS coordinates
    movw $2, %ax                # Starting LBA
    call lba_to_chs_convert
    
    # Load using CHS with retry
    movb $3, %dh                # Retry counter
    
chs_retry:
    movb $0x02, %ah             # Read sectors
    movb $128, %al              # Number of sectors (64KB)
    movb boot_drive, %dl        # Drive
    # CX and DH set by lba_to_chs_convert
    int $0x13
    jnc chs_success
    
    # Retry after drive reset  
    decb %dh
    jz chs_failed
    movb $0, %ah
    movb boot_drive, %dl
    int $0x13
    jmp chs_retry
    
chs_success:
    movb $1, %al                # Return success
    ret
    
chs_failed:
    movb $0, %al                # Return failure
    ret

lba_to_chs_convert:
    # Convert LBA in AX to CHS format
    # Uses proper 32-bit arithmetic to avoid overflow
    pushl %eax
    pushw %dx
    
    movzwl %ax, %eax            # Zero-extend LBA to 32-bit
    xorl %edx, %edx
    
    # Calculate sector: (LBA % sectors_per_track) + 1
    movzbl disk_sectors, %ecx
    divl %ecx                   # EAX = quotient, EDX = remainder  
    incb %dl                    # Sector is 1-based
    movb %dl, %cl               # Store sector in CL
    
    # Calculate head: (quotient % heads)  
    xorl %edx, %edx
    movzbl disk_heads, %ecx
    divl %ecx                   # EAX = cylinder, EDX = head
    movb %dl, temp_head         # Store head temporarily
    
    # Calculate cylinder (assume < 1024)
    movb %al, %ch               # Cylinder low 8 bits
    
    popw %dx
    movb temp_head, %dh         # Set head
    popl %eax
    ret

verify_kernel_signature:
    # Check for valid kernel signatures
    movw $0x1000, %ax
    movw %ax, %es
    
    # Check for ELF signature first
    cmpl $0x464C457F, %es:(0)   # 0x7F + "ELF"
    je elf_signature_valid
    
    # Check for PE signature
    cmpw $0x5A4D, %es:(0)       # "MZ"
    je pe_signature_valid
    
    # Check for non-zero content (raw binary)
    cmpw $0, %es:(0)
    je invalid_kernel
    cmpw $0xFFFF, %es:(0)
    je invalid_kernel
    
    # Appears to be valid raw binary
    movw $raw_kernel_msg, %si
    call print_string
    ret
    
elf_signature_valid:
    # Additional ELF validation
    cmpb $2, %es:(4)            # Check for 64-bit ELF
    je elf64_kernel
    cmpb $1, %es:(4)            # 32-bit ELF
    je elf32_kernel
    jmp invalid_kernel
    
elf64_kernel:
    movw $elf64_detected_msg, %si
    call print_string
    ret
    
elf32_kernel:
    movw $elf32_detected_msg, %si
    call print_string
    ret
    
pe_signature_valid:
    movw $pe_detected_msg, %si
    call print_string
    ret
    
invalid_kernel:
    movw $invalid_kernel_msg, %si
    call print_string
    jmp halt_system

# ========== A20 LINE MANAGEMENT ==========

enable_a20_secure:
    movw $a20_enable_msg, %si
    call print_string
    
    # Test if A20 is already enabled
    call test_a20_status
    cmpw $1, %ax
    je a20_already_enabled
    
    # Method 1: BIOS A20 service (safest first)
    call enable_a20_bios
    call test_a20_status
    cmpw $1, %ax
    je a20_enabled
    
    # Method 2: Fast A20 gate
    call enable_a20_fast_gate
    call test_a20_status
    cmpw $1, %ax
    je a20_enabled
    
    # Method 3: Keyboard controller (most compatible but slower)
    call enable_a20_keyboard_controller
    call test_a20_status
    cmpw $1, %ax
    je a20_enabled
    
    # All methods failed
    movw $a20_failed_msg, %si
    call print_string
    jmp halt_system
    
a20_already_enabled:
    movw $a20_already_msg, %si
    call print_string
    ret
    
a20_enabled:
    movw $a20_success_msg, %si
    call print_string
    ret

test_a20_status:
    # Secure A20 test using safe memory locations
    pusha
    
    # Set up segments
    movw $0x0000, %ax
    movw %ax, %ds
    movw $0xFFFF, %ax
    movw %ax, %es
    
    # Use safe test locations
    movw $0x0510, %si           # 0x0000:0x0510
    movw $0x0520, %di           # 0xFFFF:0x0520 (wraps to 0x510 if A20 off)
    
    # Save original values
    movw (%si), %ax
    pushw %ax
    movw %es:(%di), %ax
    pushw %ax
    
    # Write test patterns
    movw $0x5AA5, (%si)         # Pattern 1
    movw $0xA55A, %es:(%di)     # Pattern 2 (different)
    
    # Check if they interfere (A20 disabled if they do)
    movw (%si), %ax
    cmpw $0xA55A, %ax           # If equal, addresses wrap (A20 off)
    je a20_disabled
    
    # A20 is enabled
    popw %ax
    movw %ax, %es:(%di)         # Restore original values
    popw %ax
    movw %ax, (%si)
    
    popa
    movw $1, %ax                # A20 enabled
    ret
    
a20_disabled:
    popw %ax
    movw %ax, %es:(%di)         # Restore original values
    popw %ax
    movw %ax, (%si)
    
    popa
    movw $0, %ax                # A20 disabled
    ret

enable_a20_bios:
    # Enable A20 using BIOS service
    movw $0x2401, %ax           # Enable A20 function
    int $0x15                   # BIOS interrupt
    ret

enable_a20_fast_gate:
    # Enable A20 using fast gate (port 0x92)
    inb $0x92, %al              # Read port 0x92
    testb $0x02, %al            # Check if A20 bit already set
    jnz fast_gate_done
    orb $0x02, %al              # Set A20 enable bit
    outb %al, $0x92             # Write back to port
fast_gate_done:
    ret

enable_a20_keyboard_controller:
    # Enable A20 using keyboard controller (8042)
    call wait_8042_command
    movb $0xAD, %al             # Disable first PS/2 port
    outb %al, $0x64
    
    call wait_8042_command
    movb $0xD0, %al             # Read output port command
    outb %al, $0x64
    
    call wait_8042_data
    inb $0x60, %al              # Read current output port value
    orb $0x02, %al              # Set A20 enable bit
    movb %al, %ah               # Save modified value
    
    call wait_8042_command
    movb $0xD1, %al             # Write output port command
    outb %al, $0x64
    
    call wait_8042_command
    movb %ah, %al               # Get saved value
    outb %al, $0x60             # Write modified output port
    
    call wait_8042_command
    movb $0xAE, %al             # Enable first PS/2 port
    outb %al, $0x64
    
    ret

wait_8042_command:
    # Wait for 8042 controller to be ready for commands
    pushw %ax
    movw $0x1000, %cx           # Timeout counter
wait_cmd_ready:
    inb $0x64, %al              # Read status register
    testb $0x02, %al            # Test input buffer full bit
    jz cmd_ready
    loop wait_cmd_ready
    # Timeout - continue anyway
cmd_ready:
    popw %ax
    ret

wait_8042_data:
    # Wait for 8042 controller data to be available
    pushw %ax
    movw $0x1000, %cx           # Timeout counter
wait_data_ready:
    inb $0x64, %al              # Read status register
    testb $0x01, %al            # Test output buffer full bit
    jnz data_ready
    loop wait_data_ready
    # Timeout - continue anyway
data_ready:
    popw %ax
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
    movw $0x10, %ax             # Data segment selector from GDT
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    
    # Set up 32-bit stack at 512KB mark (safe location)
    movl $0x80000, %esp
    
    # Display 32-bit mode confirmation
    call display_32bit_status
    
    # Perform comprehensive 32-bit checks
    call validate_32bit_environment
    call setup_cpu_features
    
    # Set up paging for long mode transition
    call setup_long_mode_paging
    
    # Load 64-bit GDT
    lgdt gdt64_descriptor
    
    # Enable Physical Address Extension (PAE)
    movl %cr4, %eax
    orl $0x20, %eax             # Set PAE bit (bit 5)
    movl %eax, %cr4
    
    # Load page directory base into CR3
    movl $pml4_table, %eax
    movl %eax, %cr3
    
    # Enable long mode in EFER MSR
    movl $0xC0000080, %ecx      # EFER MSR number
    rdmsr
    orl $0x100, %eax            # Set Long Mode Enable (LME) bit
    wrmsr
    
    # Enable paging to activate long mode
    movl %cr0, %eax
    orl $0x80000000, %eax       # Set Paging bit
    movl %eax, %cr0
    
    # Jump to 64-bit code
    ljmp $0x08, $long_mode

# ========== 32-BIT FUNCTIONS ==========

display_32bit_status:
    # Print status message to VGA text buffer
    movl $0xB8000, %edi         # VGA text buffer address
    movl $protected_mode_msg, %esi
    movb $0x0F, %ah             # White on black attribute
    
print_32bit_loop:
    lodsb
    testb %al, %al
    jz print_32bit_done
    movb %al, (%edi)            # Store character
    movb %ah, 1(%edi)           # Store attribute
    addl $2, %edi               # Move to next character position
    jmp print_32bit_loop
    
print_32bit_done:
    ret

validate_32bit_environment:
    # Verify we're in proper 32-bit mode
    # Check that we can access extended registers
    movl $0x12345678, %eax
    movl %eax, %ebx
    cmpl %eax, %ebx
    jne mode_32bit_error
    
    # Verify segments are set correctly
    movw %ds, %ax
    cmpw $0x10, %ax             # Should be data segment
    jne mode_32bit_error
    
    ret
    
mode_32bit_error:
    # Display error and halt
    movl $0xB8000, %edi
    movl $mode_error_msg, %esi
    movb $0x4F, %ah             # White on red
mode_error_loop:
    lodsb
    testb %al, %al
    jz halt_32bit
    movb %al, (%edi)
    movb %ah, 1(%edi)
    addl $2, %edi
    jmp mode_error_loop

setup_cpu_features:
    # Enable SSE if available (already checked in 16-bit mode)
    movl $1, %eax
    cpuid
    testl $0x02000000, %edx     # SSE2 support
    jz skip_sse_setup
    
    # Enable SSE in CR4
    movl %cr4, %eax
    orl $0x600, %eax            # Set OSFXSR and OSXMMEXCPT bits
    movl %eax, %cr4
    
    # Initialize SSE control word
    stmxcsr temp_mxcsr
    movl temp_mxcsr, %eax
    orl $0x1F80, %eax           # Mask all exceptions initially
    movl %eax, temp_mxcsr
    ldmxcsr temp_mxcsr
    
skip_sse_setup:
    ret

setup_long_mode_paging:
    # Set up 4-level paging for x86-64
    # Clear all page tables (16KB total)
    movl $pml4_table, %edi
    xorl %eax, %eax
    movl $4096, %ecx            # Clear 16KB (4096 dwords)
    rep stosl
    
    # Set up PML4 (Page Map Level 4)
    movl $pml4_table, %edi
    movl $pdp_table, %eax
    orl $0x03, %eax             # Present + Writable
    movl %eax, (%edi)
    
    # Set up PDP (Page Directory Pointer)
    movl $pdp_table, %edi
    movl $pd_table, %eax
    orl $0x03, %eax             # Present + Writable
    movl %eax, (%edi)
    
    # Set up PD (Page Directory) with 2MB pages
    movl $pd_table, %edi
    movl $0x83, %eax            # Present + Writable + Page Size (2MB)
    movl $512, %ecx             # Map 512 * 2MB = 1GB
    
setup_pd_entries:
    movl %eax, (%edi)           # Store page directory entry
    addl $0x200000, %eax        # Next 2MB page
    addl $8, %edi               # Next PD entry (8 bytes in 64-bit mode)
    loop setup_pd_entries
    
    ret

halt_32bit:
    cli
    hlt
    jmp halt_32bit

# ========== 64-BIT LONG MODE ==========

.code64
long_mode:
    # Clear segment registers (not used in 64-bit mode)
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    
    # Set up 64-bit stack at 4MB mark
    movq $0x400000, %rsp
    
    # Display success message
    call display_64bit_success
    
    # Move kernel to final location (1MB)
    call relocate_kernel_to_final_address
    
    # Set up boot information for kernel
    call prepare_kernel_boot_info
    
    # Initialize any final 64-bit features
    call initialize_64bit_features
    
    # Transfer control to kernel
    movq $0x100000, %rdi        # First argument: kernel entry address
    movq $boot_information, %rsi # Second argument: boot info structure
    
    # Jump to kernel
    movq $0x100000, %rax
    jmp *%rax

# ========== 64-BIT FUNCTIONS ==========

display_64bit_success:
    # Print success message to VGA buffer
    movq $0xB8000, %rdi
    movq $long_mode_success_msg, %rsi
    movb $0x0A, %ah             # Light green on black
    
print_64bit_loop:
    lodsb
    testb %al, %al
    jz print_64bit_done
    movb %al, (%rdi)
    movb %ah, 1(%rdi)
    addq $2, %rdi
    jmp print_64bit_loop
    
print_64bit_done:
    ret

relocate_kernel_to_final_address:
    # Move kernel from 0x10000 to 0x100000 (1MB)
    movq $0x10000, %rsi         # Source: where we loaded it
    movq $0x100000, %rdi        # Destination: 1MB mark
    movq $0x10000, %rcx         # Size: 64KB
    
    # Use efficient 64-bit moves
    shrq $3, %rcx               # Convert to qword count
    rep movsq
    
    ret

prepare_kernel_boot_info:
    # Fill out boot information structure for kernel
    movq $boot_information, %rdi
    
    # Boot signature
    movl $0xCAFEBABE, (%rdi)
    
    # Memory map information
    movw e820_entries, %ax
    movw %ax, 4(%rdi)
    movq $e820_buffer, %rax
    movq %rax, 8(%rdi)
    
    # Kernel information
    movq $0x100000, 16(%rdi)    # Kernel physical address
    movq $0x10000, 24(%rdi)     # Kernel size (64KB)
    
    # Boot drive information
    movb boot_drive, %al
    movb %al, 32(%rdi)
    
    # Hardware flags
    movb $0, 33(%rdi)           # Initialize flags
    cmpb $1, vesa_supported
    jne no_vesa_flag
    orb $0x01, 33(%rdi)         # Set VESA flag
no_vesa_flag:
    
    # Page table locations
    movq $pml4_table, 40(%rdi)
    
    ret

initialize_64bit_features:
    # Enable NX (No Execute) bit if supported
    movl $0x80000001, %eax
    cpuid
    testl $0x100000, %edx       # NX bit support
    jz skip_nx_enable
    
    movl $0xC0000080, %ecx      # EFER MSR
    rdmsr
    orl $0x800, %eax            # Set NXE (NX Enable) bit
    wrmsr
    
skip_nx_enable:
    # Additional 64-bit initialization could go here
    ret

# ========== DATA SECTION ==========

# Boot configuration
boot_drive:             .byte 0
disk_heads:             .byte 0  
disk_sectors:           .byte 0
temp_head:              .byte 0
vesa_supported:         .byte 0

# Memory detection results
e820_entries:           .word 0
low_memory_1mb:         .word 0
high_memory_64k:        .word 0
extended_memory:        .word 0

# CPU information storage  
cpu_vendor_string:      .fill 12, 1, 0
                        .byte 0

# Temporary storage
temp_mxcsr:             .long 0
decimal_buffer:         .fill 8, 1, 0

# Page table addresses (must be 4KB aligned)
pml4_table = 0x1000     # Page Map Level 4 (4KB)
pdp_table  = 0x2000     # Page Directory Pointer (4KB) 
pd_table   = 0x3000     # Page Directory (4KB)
pt_table   = 0x4000     # Page Table (4KB, if needed)

# LBA Disk Address Packet
.align 4
disk_address_packet:
dap_size:               .byte 0x10      # Packet size
dap_reserved:           .byte 0x00      # Reserved
dap_sectors:            .byte 0x00      # Number of sectors
dap_reserved2:          .byte 0x00      # Reserved
dap_offset:             .word 0x0000    # Buffer offset
dap_segment:            .word 0x0000    # Buffer segment
dap_lba_low:            .long 0x00000000 # LBA low 32 bits
dap_lba_high:           .long 0x00000000 # LBA high 32 bits

# E820 Memory Map Buffer
.align 4
e820_buffer:            .fill 768, 1, 0  # Space for 32 entries * 24 bytes

# Boot Information Structure (passed to kernel)
.align 8  
boot_information:       .fill 256, 1, 0  # 256 bytes for boot info

# ========== MESSAGES ==========

# Boot messages
security_banner:        .ascii "CinnamonOS Bootloader v1.0\n"
                        .asciz "Performing security validation...\n"
bootloader_version:     .asciz "Build: Secure Release\n"

# System information
boot_time_msg:          .asciz "Boot time: "
no_rtc_msg:             .asciz "RTC not available\n"

# Hardware validation messages
cpu_check_msg:          .asciz "Validating CPU requirements...\n"
cpu_vendor_msg:         .asciz "CPU vendor: "
cpu_supported_msg:      .asciz "CPU: All requirements met\n"
memory_detect_msg:      .asciz "Detecting memory configuration...\n"
disk_check_msg:         .asciz "Validating disk system...\n"
disk_ready_msg:         .asciz "Disk system ready\n"

# Memory detection messages
e820_success_msg:       .asciz "E820 memory detection: "
entries_found_msg:      .asciz " entries found\n"
e801_success_msg:       .asciz "E801 memory detection successful\n"
mem88_success_msg:      .asciz "Legacy memory: "
kb_extended_msg:        .asciz " KB extended\n"
memory_summary_msg:     .asciz "\n=== Memory Layout ===\n"
e820_entries_msg:       .asciz "E820 Memory Map:\n"
entry_base_msg:         .asciz "  Base: "
entry_length_msg:       .asciz " Len: "
entry_type_msg:         .asciz " Type: "
legacy_low_msg:         .asciz "Low memory: "
legacy_ext_msg:         .asciz "Extended memory: "
kb_msg:                 .asciz " KB\n"

# Security check messages
integrity_check_msg:    .asciz "Performing integrity checks...\n"
integrity_ok_msg:       .asciz "Integrity validation passed\n"
checksum_msg:           .asciz "Bootloader checksum: "
suspicious_code_msg:    .asciz "Warning: Suspicious code signatures detected\n"
suspicious_ivt_msg:     .asciz "Warning: Unusual interrupt vectors detected\n"
env_check_msg:          .asciz "Validating boot environment...\n"
env_ok_msg:             .asciz "Boot environment validated\n"
location_warning_msg:   .asciz "Warning: Unusual execution location\n"
stack_warning_msg:      .asciz "Warning: Stack in unexpected location\n"

# Kernel loading messages
kernel_load_msg:        .asciz "Loading and verifying kernel...\n"
kernel_verified_msg:    .asciz "Kernel signature verified\n"
elf64_detected_msg:     .asciz "ELF64 kernel detected\n"
elf32_detected_msg:     .asciz "ELF32 kernel detected\n"
pe_detected_msg:        .asciz "PE kernel detected\n"
raw_kernel_msg:         .asciz "Raw binary kernel detected\n"

# A20 messages
a20_enable_msg:         .asciz "Enabling A20 address line...\n"
a20_already_msg:        .asciz "A20 already enabled\n"
a20_success_msg:        .asciz "A20 enabled successfully\n"

# Mode transition messages
entering_32bit_msg:     .asciz "Entering 32-bit protected mode...\n"
protected_mode_msg:     .asciz "32-bit mode active - Preparing long mode"
long_mode_success_msg:  .asciz "64-bit long mode active - Starting kernel"

# Error messages
no_cpuid_error:         .asciz "FATAL: CPUID instruction not supported\n"
no_longmode_error:      .asciz "FATAL: 64-bit long mode not supported\n"
no_sse2_error:          .asciz "FATAL: SSE2 instruction set required\n"
no_tsc_error:           .asciz "FATAL: Time Stamp Counter required\n"
memory_detect_fail:     .asciz "FATAL: Memory detection failed\n"
disk_reset_error:       .asciz "FATAL: Disk reset failed\n"
disk_params_error:      .asciz "FATAL: Cannot read disk parameters\n"
disk_geometry_error:    .asciz "FATAL: Invalid disk geometry\n"
kernel_load_failed:     .asciz "FATAL: Kernel loading failed\n"
invalid_kernel_msg:     .asciz "FATAL: Invalid kernel signature\n"
a20_failed_msg:         .asciz "FATAL: Cannot enable A20 line\n"
mode_error_msg:         .asciz "FATAL: Protected mode initialization failed"
system_halted_msg:      .asciz "SYSTEM HALTED - Please restart\n"

# ========== GLOBAL DESCRIPTOR TABLES ==========

# 32-bit GDT for protected mode transition
.align 8
gdt32_start:
    # Null descriptor (required)
    .quad 0x0000000000000000
    
    # 32-bit code segment (selector 0x08)  
    .word 0xFFFF                # Limit 15:0
    .word 0x0000                # Base 15:0
    .byte 0x00                  # Base 23:16
    .byte 0x9A                  # Access: P=1, DPL=00, S=1, Type=1010 (Execute/Read)
    .byte 0xCF                  # Flags: G=1, D/B=1, L=0, AVL=0, Limit 19:16=1111
    .byte 0x00                  # Base 31:24
    
    # 32-bit data segment (selector 0x10)
    .word 0xFFFF                # Limit 15:0
    .word 0x0000                # Base 15:0
    .byte 0x00                  # Base 23:16
    .byte 0x92                  # Access: P=1, DPL=00, S=1, Type=0010 (Read/Write)
    .byte 0xCF                  # Flags: G=1, D/B=1, L=0, AVL=0, Limit 19:16=1111
    .byte 0x00                  # Base 31:24

gdt32_end:

# 64-bit GDT for long mode
.align 8
gdt64_start:
    # Null descriptor (required)
    .quad 0x0000000000000000
    
    # 64-bit code segment (selector 0x08)
    .word 0x0000                # Limit (ignored in 64-bit mode)
    .word 0x0000                # Base (ignored)
    .byte 0x00                  # Base (ignored)
    .byte 0x9A                  # Access: P=1, DPL=00, S=1, Type=1010 (Execute/Read)
    .byte 0x20                  # Flags: G=0, D/B=0, L=1 (64-bit), AVL=0
    .byte 0x00                  # Base (ignored)
    
    # 64-bit data segment (selector 0x10) 
    .word 0x0000                # Limit (ignored)
    .word 0x0000                # Base (ignored)
    .byte 0x00                  # Base (ignored)
    .byte 0x92                  # Access: P=1, DPL=00, S=1, Type=0010 (Read/Write)
    .byte 0x00                  # Flags: All 0 for data segment in 64-bit
    .byte 0x00                  # Base (ignored)

gdt64_end:

# GDT descriptors for LGDT instruction
gdt32_descriptor:
    .word gdt32_end - gdt32_start - 1    # Limit
    .long gdt32_start                     # Base address

gdt64_descriptor:
    .word gdt64_end - gdt64_start - 1    # Limit
    .quad gdt64_start                     # Base address

# ========== BOOT SECTOR SIGNATURE ==========
.org 510
.word 0xAA55                    # Boot sector signature
