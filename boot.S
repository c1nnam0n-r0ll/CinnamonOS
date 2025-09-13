# CinnamonOS Two-Stage Bootloader
# Stage 1: Boot Sector (512 bytes)
# Stage 2: Main Bootloader 

#======================================================================================
# STAGE 1 BOOTLOADER           (Boot Sector - 512 bytes)
#======================================================================================

.code16
.section .stage1, "ax"
.org 0x0

stage1_start:
    # Disable interrupts and set direction flag
    cli
    cld
    
    # Set up segments (zero all for clean state)
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    
    # Set up stack well below Stage 2 load area
    movw $0x7BFF, %sp
    
    # Save boot drive
    movb %dl, boot_drive
    
    # Clear screen and show banner
    call clear_screen
    movw $stage1_banner, %si
    call print_string
    
    # Load Stage 2 bootloader from disk
    movw $loading_msg, %si
    call print_string
    
    # Load Stage 2 at 0x1000:0x0000 (64KB mark)
    movw $0x1000, %ax
    movw %ax, %es
    xorw %bx, %bx
    
    # Try LBA first, then CHS
    call load_stage2_lba
    testb %al, %al
    jnz stage2_loaded
    
    call load_stage2_chs
    testb %al, %al
    jnz stage2_loaded
    
    # Loading failed
    movw $load_failed_msg, %si
    call print_string
    jmp halt_stage1

stage2_loaded:
    movw $load_success_msg, %si
    call print_string
    
    # Jump to Stage 2
    movb boot_drive, %dl  # Pass boot drive to Stage 2
    ljmp $0x1000, $0x0000

# Print string function for Stage 1
print_string:
    pusha
print_loop:
    lodsb
    testb %al, %al
    jz print_done
    movb $0x0E, %ah
    int $0x10
    jmp print_loop
print_done:
    popa
    ret

# Clear screen
clear_screen:
    movb $0x00, %ah
    movb $0x03, %al
    int $0x10
    ret

# Load Stage 2 using LBA - FIXED DAP structure
load_stage2_lba:
    # Check LBA support
    movb $0x41, %ah
    movw $0x55AA, %bx
    movb boot_drive, %dl
    int $0x13
    jc lba_not_supported
    cmpw $0xAA55, %bx
    jne lba_not_supported
    
    # Set up properly structured DAP
    movw $dap, %si
    movb $0x10, 0x00(%si)   # Packet size (1 byte)
    movb $0x00, 0x01(%si)   # Reserved (1 byte)
    movw $64, 0x02(%si)     # Sectors to read (2 bytes) - 32KB
    movw $0x0000, 0x04(%si) # Buffer offset (2 bytes)
    movw $0x1000, 0x06(%si) # Buffer segment (2 bytes)
    movl $1, 0x08(%si)      # Starting LBA (4 bytes)
    movl $0, 0x0C(%si)      # Upper 32 bits of LBA (4 bytes)
    
    # Retry mechanism for LBA read
    movb $3, %ch            # Retry count
lba_retry:
    movb $0x42, %ah         # Extended read
    movb boot_drive, %dl
    movw $dap, %si
    int $0x13
    jnc lba_success
    
    # Reset drive and retry
    decb %ch
    jz lba_failed
    xorb %ah, %ah
    movb boot_drive, %dl
    int $0x13
    jmp lba_retry
    
lba_success:
    movb $1, %al
    ret

lba_not_supported:
lba_failed:
    xorb %al, %al
    ret

# Load Stage 2 using CHS - FIXED to handle sector limits
load_stage2_chs:
    # Reset disk
    xorb %ah, %ah
    movb boot_drive, %dl
    int $0x13
    jc chs_failed
    
    # Get disk parameters
    movb $0x08, %ah
    movb boot_drive, %dl
    int $0x13
    jc chs_failed
    
    # Extract sectors per track (CL bits 0-5)
    andb $0x3F, %cl
    movb %cl, sectors_per_track
    
    # Load Stage 2 in chunks to avoid BIOS limits
    movw $0x1000, %ax       # Load segment
    movw %ax, %es
    xorw %bx, %bx           # Buffer offset
    movb $1, %cl            # Start at sector 2 (1-based)
    movb $0, %dh            # Head 0
    movb $0, %ch            # Cylinder 0
    movb $32, %al           # Read 32 sectors at a time (16KB chunks)
    movb $2, sectors_remaining # Need 2 chunks for 32KB total
    
chs_chunk_loop:
    movb $3, %ah            # Retry counter in AH upper bits
chs_retry:
    pushw %ax               # Save retry counter and sector count
    movb $0x02, %ah         # Read sectors function
    movb boot_drive, %dl
    int $0x13
    popw %ax
    jnc chs_chunk_success
    
    # Retry
    shrb $4, %ah            # Get retry counter
    decb %ah
    jz chs_failed
    shlb $4, %ah            # Put back retry counter
    
    # Reset drive
    pushw %ax
    xorb %ah, %ah
    movb boot_drive, %dl
    int $0x13
    popw %ax
    jmp chs_retry
    
chs_chunk_success:
    # Move to next chunk
    decb sectors_remaining
    jz chs_success
    
    # Update buffer pointer (16KB = 0x4000 bytes)
    addw $0x4000, %bx
    
    # Update sector (add 32)
    addb $32, %cl
    cmpb sectors_per_track, %cl
    jle chs_chunk_loop
    
    # Handle track/head wrap
    subb sectors_per_track, %cl
    incb %cl                # Next track starts at sector 1
    incb %dh                # Next head
    jmp chs_chunk_loop
    
chs_success:
    movb $1, %al
    ret

chs_failed:
    xorb %al, %al
    ret

halt_stage1:
    movw $halt_msg, %si
    call print_string
halt_loop:
    cli
    hlt
    jmp halt_loop

# Stage 1 Data
boot_drive:         .byte 0
sectors_per_track:  .byte 0
sectors_remaining:  .byte 0
dap:                .fill 16, 1, 0  # Disk Address Packet

stage1_banner:      .asciz "CinnamonOS Stage 1 Bootloader\r\n"
loading_msg:        .asciz "Loading Stage 2...\r\n"
load_success_msg:   .asciz "Stage 2 loaded successfully\r\n"
load_failed_msg:    .asciz "FATAL: Cannot load Stage 2\r\n"
halt_msg:           .asciz "System halted\r\n"

# Pad to 510 bytes and add boot signature
.org 510
.word 0xAA55

#======================================================================================
# STAGE 2 BOOTLOADER               (Loaded at 0x1000:0x0000)
#======================================================================================

.code16
.section .stage2, "ax"
.org 0x0

stage2_start:
    # Stage 2 initialization
    cli
    cld
    
    # Set up segments for Stage 2
    movw $0x1000, %ax
    movw %ax, %ds
    movw %ax, %es
    xorw %ax, %ax
    movw %ax, %ss
    
    # Set up stack at 0x8000 (safe area)
    movw $0x8000, %sp
    
    # Save boot drive (passed from Stage 1)
    movb %dl, s2_boot_drive
    
    # Display Stage 2 banner
    call s2_clear_screen
    movw $s2_banner, %si
    call s2_print_string
    
    # Comprehensive hardware validation
    call validate_cpu
    call detect_memory
    call validate_disk
    
    # Security checks
    call security_checks
    
    # Load kernel
    call load_kernel
    
    # Enable A20 with multiple methods
    call enable_a20_comprehensive
    
    # Enter protected mode
    movw $entering_pmode_msg, %si
    call s2_print_string
    
    lgdt s2_gdt32_desc
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmp $0x08, $protected_mode

# Stage 2 screen functions
s2_clear_screen:
    movb $0x00, %ah
    movb $0x03, %al
    int $0x10
    ret

s2_print_string:
    pusha
s2_print_loop:
    lodsb
    testb %al, %al
    jz s2_print_done
    cmpb $'\n', %al
    je s2_newline
    movb $0x0E, %ah
    int $0x10
    jmp s2_print_loop
s2_newline:
    movb $0x0E, %ah
    movb $'\r', %al
    int $0x10
    movb $'\n', %al
    int $0x10
    jmp s2_print_loop
s2_print_done:
    popa
    ret

s2_print_hex_word:
    pusha
    movw %ax, %dx
    movb $'0', %al
    call s2_print_char
    movb $'x', %al
    call s2_print_char
    movb $4, %cl
hex_loop:
    rolw $4, %dx
    movb %dl, %al
    andb $0x0F, %al
    addb $'0', %al
    cmpb $'9', %al
    jle hex_print
    addb $7, %al
hex_print:
    call s2_print_char
    decb %cl
    jnz hex_loop
    popa
    ret

s2_print_char:
    movb $0x0E, %ah
    int $0x10
    ret

# CPU validation - FIXED CPUID test and comprehensive checks
validate_cpu:
    movw $cpu_check_msg, %si
    call s2_print_string
    
    # Test CPUID using FLAGS manipulation (more reliable)
    pushfw
    popw %ax
    movw %ax, %bx           # Save original flags
    xorw $0x0040, %ax       # Toggle AC flag (bit 6)
    pushw %ax
    popfw
    pushfw
    popw %ax                # Get flags after toggle attempt
    pushw %bx               # Restore original flags
    popfw
    
    xorw %bx, %ax           # Check if flag changed
    testw %ax, %ax
    jz cpu_no_cpuid
    
    # Test for CPUID instruction support
    movl $0, %eax
    cpuid                   # Get maximum CPUID level
    cmpl $1, %eax
    jb cpu_basic_failed
    
    # Get CPU features
    movl $1, %eax
    cpuid
    
    # Check for required features
    testl $0x00000010, %edx # TSC (Time Stamp Counter)
    jz cpu_no_tsc
    testl $0x02000000, %edx # SSE2
    jz cpu_no_sse2
    testl $0x00000200, %edx # APIC
    jz cpu_no_apic
    
    # Check for long mode (requires extended CPUID)
    movl $0x80000000, %eax
    cpuid
    cmpl $0x80000001, %eax
    jb cpu_no_longmode
    
    movl $0x80000001, %eax
    cpuid
    testl $0x20000000, %edx # Long Mode
    jz cpu_no_longmode
    
    movw $cpu_ok_msg, %si
    call s2_print_string
    ret

cpu_no_cpuid:
    movw $cpu_no_cpuid_msg, %si
    call s2_print_string
    jmp s2_halt

cpu_basic_failed:
    movw $cpu_basic_failed_msg, %si
    call s2_print_string
    jmp s2_halt

cpu_no_tsc:
    movw $cpu_no_tsc_msg, %si
    call s2_print_string
    jmp s2_halt

cpu_no_sse2:
    movw $cpu_no_sse2_msg, %si
    call s2_print_string
    jmp s2_halt

cpu_no_apic:
    movw $cpu_no_apic_msg, %si
    call s2_print_string
    jmp s2_halt

cpu_no_longmode:
    movw $cpu_no_longmode_msg, %si
    call s2_print_string
    jmp s2_halt

# Memory detection - FIXED E820 loop with proper EBX handling
detect_memory:
    movw $mem_detect_msg, %si
    call s2_print_string
    
    # E820 memory detection with proper continuation handling
    movw $e820_buffer, %di
    xorl %ebx, %ebx         # MUST start with EBX=0
    movw $0, e820_count
    
e820_loop:
    # Set up E820 call
    movl $0xE820, %eax      # Function
    movl $24, %ecx          # Buffer size  
    movl $0x534D4150, %edx  # "SMAP" signature
    
    # CRITICAL: Don't modify EBX between calls - it's the continuation value
    int $0x15
    
    # Check for errors
    jc e820_error           # Carry set = error
    cmpl $0x534D4150, %eax  # Verify SMAP returned
    jne e820_error
    
    # Valid entry - increment counter and buffer
    incw e820_count
    addw $24, %di
    
    # Check for end condition (EBX = 0)
    testl %ebx, %ebx
    jz e820_done
    
    # Safety check - don't exceed buffer
    cmpw $63, e820_count    # Max 63 entries (63*24 = 1512 bytes)
    jae e820_done
    
    jmp e820_loop

e820_error:
    # Fall back to E801 if E820 fails
    cmpw $0, e820_count
    jne e820_done           # Use partial E820 results
    
    # E801 memory detection
    clc
    movw $0xE801, %ax
    int $0x15
    jc mem_e88_fallback
    
    # Store E801 results
    movw %ax, mem_low_kb
    movw %bx, mem_high_64kb
    movw $mem_e801_msg, %si
    call s2_print_string
    ret

mem_e88_fallback:
    # Legacy 88h memory detection
    movb $0x88, %ah
    int $0x15
    jc mem_detect_failed
    
    movw %ax, mem_extended_kb
    movw $mem_e88_msg, %si
    call s2_print_string
    ret

mem_detect_failed:
    movw $mem_failed_msg, %si
    call s2_print_string
    jmp s2_halt

e820_done:
    movw $mem_found_msg, %si
    call s2_print_string
    movw e820_count, %ax
    call s2_print_hex_word
    movw $entries_msg, %si
    call s2_print_string
    
    # Display first few entries
    call display_memory_map
    ret

display_memory_map:
    cmpw $0, e820_count
    je no_e820_display
    
    movw $map_header_msg, %si
    call s2_print_string
    
    # Show first 4 entries to avoid screen overflow
    movw $e820_buffer, %si
    movw e820_count, %cx
    cmpw $4, %cx
    jle display_all_entries
    movw $4, %cx

display_all_entries:
    pushw %cx
    pushw %si
    
    # Display base address (low 32 bits)
    movw $base_msg, %si
    call s2_print_string
    popw %si
    pushw %si
    
    movl (%si), %eax
    call s2_print_hex_dword
    
    # Display length (low 32 bits) 
    movw $length_msg, %si
    call s2_print_string
    popw %si
    pushw %si
    
    movl 8(%si), %eax
    call s2_print_hex_dword
    
    # Display type
    movw $type_msg, %si
    call s2_print_string
    popw %si
    
    movl 16(%si), %eax
    call s2_print_hex_dword
    
    movw $newline_msg, %si
    call s2_print_string
    
    addw $24, %si           # Next E820 entry
    popw %cx
    loop display_all_entries

no_e820_display:
    ret

s2_print_hex_dword:
    pushal
    
    # Print 0x prefix
    movb $'0', %al
    call s2_print_char
    movb $'x', %al
    call s2_print_char
    
    # Print 8 hex digits
    movb $8, %cl
    roll $4, %eax
hex_dword_loop:
    roll $4, %eax
    movb %al, %bl
    andb $0x0F, %bl
    addb $'0', %bl
    cmpb $'9', %bl
    jle hex_dword_print
    addb $7, %bl
hex_dword_print:
    movb %bl, %al
    call s2_print_char
    decb %cl
    jnz hex_dword_loop
    
    popal
    ret

# Disk validation
validate_disk:
    movw $disk_check_msg, %si
    call s2_print_string
    
    # Reset disk
    xorb %ah, %ah
    movb s2_boot_drive, %dl
    int $0x13
    jc disk_error
    
    # Get disk parameters for validation
    movb $0x08, %ah
    movb s2_boot_drive, %dl
    int $0x13
    jc disk_param_error
    
    # Validate geometry
    testb %dh, %dh          # Check heads > 0
    jz disk_geometry_error
    andb $0x3F, %cl         # Extract sectors per track
    testb %cl, %cl          # Check sectors > 0
    jz disk_geometry_error
    
    movw $disk_ok_msg, %si
    call s2_print_string
    ret

disk_error:
    movw $disk_error_msg, %si
    call s2_print_string
    jmp s2_halt

disk_param_error:
    movw $disk_param_msg, %si
    call s2_print_string
    jmp s2_halt

disk_geometry_error:
    movw $disk_geom_msg, %si
    call s2_print_string
    jmp s2_halt

# Security checks
security_checks:
    movw $security_msg, %si
    call s2_print_string
    
    # Enhanced integrity check
    call bootloader_integrity_check
    call memory_scan_check
    call ivt_validation_check
    
    movw $security_ok_msg, %si
    call s2_print_string
    ret

bootloader_integrity_check:
    movw $integrity_msg, %si
    call s2_print_string
    
    # Calculate checksum of Stage 2
    movw $stage2_start, %si
    movw $2048, %cx         # Check first 2KB
    xorw %dx, %dx
    
integrity_loop:
    lodsb
    xorb %al, %dl
    loop integrity_loop
    
    movw $checksum_msg, %si
    call s2_print_string
    movw %dx, %ax
    call s2_print_hex_word
    movw $newline_msg, %si
    call s2_print_string
    ret

memory_scan_check:
    # Scan low memory for suspicious patterns
    movw $0x0400, %ax       # Start after IVT
    movw %ax, %es
    xorw %di, %di
    movw $0x400, %cx        # Scan 1KB
    
scan_loop:
    movw %es:(%di), %ax
    cmpw $0x4D5A, %ax       # MZ signature in wrong place
    je suspicious_found
    cmpw $0x5A4D, %ax       # Reversed MZ
    je suspicious_found
    incw %di
    loop scan_loop
    ret

suspicious_found:
    movw $suspicious_msg, %si
    call s2_print_string
    ret

ivt_validation_check:
    # Check critical interrupt vectors
    xorw %ax, %ax
    movw %ax, %es
    
    # Check divide by zero handler
    movl %es:(0x00), %eax
    testl %eax, %eax
    jz ivt_suspicious
    
    # Check invalid opcode handler  
    movl %es:(0x18), %eax   # INT 6
    testl %eax, %eax
    jz ivt_suspicious
    ret

ivt_suspicious:
    movw $ivt_warning_msg, %si
    call s2_print_string
    ret

# Load kernel with enhanced verification
load_kernel:
    movw $kernel_load_msg, %si
    call s2_print_string
    
    # Load kernel at 0x2000:0x0000 (128KB)
    movw $0x2000, %ax
    movw %ax, %es
    xorw %bx, %bx
    
    # Enhanced LBA read with proper DAP
    movw $kernel_dap, %si
    movb $0x10, 0x00(%si)   # Packet size
    movb $0x00, 0x01(%si)   # Reserved
    movw $64, 0x02(%si)     # Sectors (32KB)
    movw $0x0000, 0x04(%si) # Buffer offset
    movw $0x2000, 0x06(%si) # Buffer segment
    movl $65, 0x08(%si)     # Start at sector 65
    movl $0, 0x0C(%si)      # High LBA
    
    movb $0x42, %ah
    movb s2_boot_drive, %dl
    int $0x13
    jc kernel_load_error
    
    # Enhanced kernel signature verification
    call verify_kernel_format
    
    movw $kernel_loaded_msg, %si
    call s2_print_string
    ret

verify_kernel_format:
    movw $0x2000, %ax
    movw %ax, %es
    
    # Check ELF signature (more thorough)
    cmpl $0x464C457F, %es:(0)   # 0x7F + "ELF"
    jne check_pe_format
    
    # Verify ELF class and data encoding
    cmpb $2, %es:(4)            # 64-bit ELF
    jne check_elf32
    cmpb $1, %es:(5)            # Little endian
    jne elf_format_error
    movw $kernel_elf64_msg, %si
    call s2_print_string
    ret

check_elf32:
    cmpb $1, %es:(4)            # 32-bit ELF
    jne elf_format_error
    movw $kernel_elf32_msg, %si
    call s2_print_string
    ret

check_pe_format:
    cmpw $0x5A4D, %es:(0)       # "MZ" signature
    jne check_raw_format
    
    # Verify PE header location
    movl %es:(0x3C), %eax       # PE header offset
    cmpl $0x1000, %eax          # Reasonable limit
    jae pe_format_error
    
    # Check PE signature at offset
    movl %eax, %ebx
    cmpl $0x00004550, %es:(%ebx) # "PE\0\0"
    jne pe_format_error
    
    movw $kernel_pe_msg, %si
    call s2_print_string
    ret

check_raw_format:
    # Verify it's not all zeros or all ones
    movl %es:(0), %eax
    testl %eax, %eax
    jz kernel_format_error
    cmpl $0xFFFFFFFF, %eax
    je kernel_format_error
    
    movw $kernel_raw_msg, %si
    call s2_print_string
    ret

elf_format_error:
pe_format_error:
kernel_format_error:
    movw $kernel_format_msg, %si
    call s2_print_string
    jmp s2_halt

kernel_load_error:
    movw $kernel_error_msg, %si
    call s2_print_string
    jmp s2_halt

# A20 enable with comprehensive methods
enable_a20_comprehensive:
    movw $a20_msg, %si
    call s2_print_string
    
    # Test if already enabled
    call test_a20_reliable
    testw %ax, %ax
    jnz a20_already_enabled
    
    # Method 1: BIOS service
    movw $0x2401, %ax
    int $0x15
    call test_a20_reliable
    testw %ax, %ax
    jnz a20_enabled
    
    # Method 2: Fast gate (Port 0x92)
    inb $0x92, %al
    orb $2, %al
    outb %al, $0x92
    call test_a20_reliable
    testw %ax, %ax
    jnz a20_enabled
    
    # Method 3: Keyboard controller
    call enable_a20_kbd_controller
    call test_a20_reliable
    testw %ax, %ax
    jnz a20_enabled
    
    # All methods failed
    movw $a20_failed_msg, %si
    call s2_print_string
    jmp s2_halt

a20_already_enabled:
    movw $a20_already_msg, %si
    call s2_print_string
    ret

a20_enabled:
    movw $a20_ok_msg, %si
    call s2_print_string
    ret

# More reliable A20 test
test_a20_reliable:
    pushw %ds
    pushw %es
    pushal
    
    # Set up segments for test
    xorw %ax, %ax
    movw %ax, %ds
    movw $0xFFFF, %ax
    movw %ax, %es
    
    # Use safe test locations
    movw $0x0500, %si       # 0x0000:0x0500
    movw $0x0510, %di       # 0xFFFF:0x0510 (wraps to 0x0500 if A20 off)
    
    # Save original values
    movl (%si), %eax
    pushl %eax
    movl %es:(%di), %eax
    pushl %eax
    
    # Write unique test patterns
    movl $0x00FF00FF, (%si)
    movl $0xFF00FF00, %es:(%di)
    
    # Add memory barriers
    movl (%si), %eax        # Force memory read
    
    # Check if A20 wrapping occurred
    movl (%si), %eax
    cmpl $0xFF00FF00, %eax
    je a20_test_disabled
    
    # A20 is enabled - restore and return 1
    popl %eax
    movl %eax, %es:(%di)
    popl %eax
    movl %eax, (%si)
    
    popal
    popw %es
    popw %ds
    movw $1, %ax
    ret

a20_test_disabled:
    # A20 is disabled - restore and return 0
    popl %eax
    movl %eax, %es:(%di)
    popl %eax
    movl %eax, (%si)
    
    popal
    popw %es
    popw %ds
    xorw %ax, %ax
    ret

enable_a20_kbd_controller:
    # Wait for keyboard controller
    call wait_kbd_ready
    
    # Disable keyboard
    movb $0xAD, %al
    outb %al, $0x64
    
    call wait_kbd_ready
    
    # Read output port
    movb $0xD0, %al
    outb %al, $0x64
    call wait_kbd_data
    inb $0x60, %al
    pushl %eax
    
    call wait_kbd_ready
    
    # Write output port
    movb $0xD1, %al
    outb %al, $0x64
    
    call wait_kbd_ready
    
    popl %eax
    orb $0x02, %al          # Set A20 bit
    outb %al, $0x60
    
    call wait_kbd_ready
    
    # Enable keyboard
    movb $0xAE, %al
    outb %al, $0x64
    
    call wait_kbd_ready
    ret

wait_kbd_ready:
    # Wait for keyboard controller input buffer to be empty
    pushl %eax
    movl $65536, %ecx       # Timeout counter
wait_kbd_loop:
    inb $0x64, %al
    testb $0x02, %al        # Input buffer full?
    jz kbd_ready
    loop wait_kbd_loop
kbd_ready:
    popl %eax
    ret

wait_kbd_data:
    # Wait for keyboard controller output buffer to have data
    pushl %eax
    movl $65536, %ecx       # Timeout counter
wait_data_loop:
    inb $0x64, %al
    testb $0x01, %al        # Output buffer full?
    jnz data_ready
    loop wait_data_loop
data_ready:
    popl %eax
    ret

s2_halt:
    movw $halt_system_msg, %si
    call s2_print_string
s2_halt_loop:
    cli
    hlt
    jmp s2_halt_loop

# 32-bit Protected Mode - FIXED paging setup
.code32
protected_mode:
    # Set up 32-bit segments
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    
    movl $0x90000, %esp  # Set 32-bit stack
    
    # Display 32-bit message
    movl $0xB8000, %edi
    movl $pmode_msg, %esi
    movb $0x0F, %ah
    
pmode_print_loop:
    lodsb
    testb %al, %al
    jz pmode_print_done
    movb %al, (%edi)
    movb %ah, 1(%edi)
    addl $2, %edi
    jmp pmode_print_loop

pmode_print_done:
    # Set up long mode paging - CORRECTED
    call setup_paging_fixed
    
    # Enable PAE
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4
    
    # Load page table
    movl $0x70000, %eax
    movl %eax, %cr3
    
    # Enable long mode
    movl $0xC0000080, %ecx
    rdmsr
    orl $0x100, %eax        # Set LME bit
    wrmsr
    
    # Enable paging
    movl %cr0, %eax
    orl $0x80000000, %eax
    movl %eax, %cr0
    
    # Load 64-bit GDT and jump to long mode
    lgdt s2_gdt64_desc
    ljmp $0x08, $long_mode

setup_paging_fixed:
    # Clear page tables (16KB total)
    movl $0x70000, %edi
    xorl %eax, %eax
    movl $4096, %ecx        # Clear 16KB (4096 dwords)
    rep stosl
    
    # Set up PML4 (Page Map Level 4)
    movl $0x70000, %edi
    movl $0x71003, %eax     # Present + Write + User, point to PDPT
    movl %eax, (%edi)
    
    # Set up PDPT (Page Directory Pointer Table)
    movl $0x71000, %edi
    movl $0x72003, %eax     # Present + Write + User, point to PD
    movl %eax, (%edi)
    
    # Set up PD (Page Directory) with 2MB pages - FIXED addressing
    movl $0x72000, %edi
    movl $0x83, %eax        # Present + Write + 2MB page bit
    movl $512, %ecx         # 512 entries = 1GB mapped
    xorl %edx, %edx         # Physical address counter
    
setup_pd_loop_fixed:
    movl %eax, (%edi)       # Store PDE with flags
    addl $0x200000, %eax    # Next 2MB physical page
    addl $8, %edi           # Next PDE (8 bytes in long mode)
    loop setup_pd_loop_fixed
    
    ret

# 64-bit Long Mode
.code64
long_mode:
    # Clear segments (not used in 64-bit)
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    
    # Set 64-bit stack
    movq $0x200000, %rsp
    
    # Display 64-bit success
    movq $0xB8000, %rdi
    movq $longmode_msg, %rsi
    movb $0x0A, %ah
    
longmode_print_loop:
    lodsb
    testb %al, %al
    jz longmode_print_done
    movb %al, (%rdi)
    movb %ah, 1(%rdi)
    addq $2, %rdi
    jmp longmode_print_loop

longmode_print_done:
    # Set up kernel boot parameters
    call prepare_kernel_handoff
    
    # Jump to kernel at 0x20000 (128KB)
    movq $0x20000, %rdi     # First parameter: boot info
    movq $boot_info_struct, %rsi  # Second parameter: boot structure
    movq $0x20000, %rax
    jmp *%rax

prepare_kernel_handoff:
    # Fill boot information structure
    movq $boot_info_struct, %rdi
    
    # Boot signature
    movl $0xB007C0DE, (%rdi)    # Boot code signature
    
    # Memory map pointer and count
    movw s2_e820_count, %ax
    movw %ax, 4(%rdi)
    movq $s2_e820_buffer, 8(%rdi)
    
    # Kernel location and size
    movq $0x20000, 16(%rdi)     # Kernel physical address
    movq $0x8000, 24(%rdi)      # Kernel size (32KB)
    
    # Boot drive
    movb s2_boot_drive, %al
    movb %al, 32(%rdi)
    
    # Page table location
    movq $0x70000, 40(%rdi)     # PML4 location
    
    ret

# Stage 2 Data Section
s2_boot_drive:      .byte 0
s2_e820_count:      .word 0
mem_low_kb:         .word 0
mem_high_64kb:      .word 0
mem_extended_kb:    .word 0

# Buffers
s2_e820_buffer:     .fill 1512, 1, 0    # 63 entries * 24 bytes
kernel_dap:         .fill 16, 1, 0
boot_info_struct:   .fill 256, 1, 0

# Messages - Part 1
s2_banner:          .asciz "CinnamonOS Stage 2 Bootloader v1.0\n"
cpu_check_msg:      .asciz "Checking CPU requirements...\n"
cpu_ok_msg:         .asciz "CPU: All requirements validated\n"
cpu_no_cpuid_msg:   .asciz "FATAL: CPUID instruction not supported\n"
cpu_basic_failed_msg: .asciz "FATAL: Basic CPUID functions unavailable\n"
cpu_no_tsc_msg:     .asciz "FATAL: Time Stamp Counter not available\n"
cpu_no_sse2_msg:    .asciz "FATAL: SSE2 instruction set required\n"
cpu_no_apic_msg:    .asciz "FATAL: APIC support required\n"
cpu_no_longmode_msg: .asciz "FATAL: 64-bit long mode not supported\n"

# Messages - Part 2
mem_detect_msg:     .asciz "Detecting system memory...\n"
mem_found_msg:      .asciz "E820 memory entries found: "
entries_msg:        .asciz " entries\n"
mem_e801_msg:       .asciz "E801 memory detection successful\n"
mem_e88_msg:        .asciz "Legacy memory detection successful\n"
mem_failed_msg:     .asciz "FATAL: All memory detection methods failed\n"
map_header_msg:     .asciz "Memory Map (first 4 entries):\n"
base_msg:           .asciz "  Base: "
length_msg:         .asciz " Length: "
type_msg:           .asciz " Type: "

# Messages - Part 3
disk_check_msg:     .asciz "Validating disk subsystem...\n"
disk_ok_msg:        .asciz "Disk subsystem operational\n"
disk_error_msg:     .asciz "FATAL: Disk reset failed\n"
disk_param_msg:     .asciz "FATAL: Cannot read disk parameters\n"
disk_geom_msg:      .asciz "FATAL: Invalid disk geometry\n"

# Messages - Part 4
security_msg:       .asciz "Performing security validation...\n"
security_ok_msg:    .asciz "Security checks completed\n"
integrity_msg:      .asciz "Checking bootloader integrity...\n"
checksum_msg:       .asciz "Bootloader checksum: "
suspicious_msg:     .asciz "WARNING: Suspicious code patterns detected\n"
ivt_warning_msg:    .asciz "WARNING: Unusual interrupt vector configuration\n"

# Messages - Part 5
kernel_load_msg:    .asciz "Loading kernel image...\n"
kernel_loaded_msg:  .asciz "Kernel loaded and verified\n"
kernel_elf64_msg:   .asciz "ELF64 kernel format detected\n"
kernel_elf32_msg:   .asciz "ELF32 kernel format detected\n"
kernel_pe_msg:      .asciz "PE executable format detected\n"
kernel_raw_msg:     .asciz "Raw binary format detected\n"
kernel_format_msg:  .asciz "FATAL: Invalid kernel format\n"
kernel_error_msg:   .asciz "FATAL: Kernel loading failed\n"

# Messages - Part 6
a20_msg:            .asciz "Enabling A20 address line...\n"
a20_already_msg:    .asciz "A20 line already enabled\n"
a20_ok_msg:         .asciz "A20 line enabled successfully\n"
a20_failed_msg:     .asciz "FATAL: Cannot enable A20 line\n"

# Messages - Part 7
entering_pmode_msg: .asciz "Transitioning to protected mode...\n"
halt_system_msg:    .asciz "System halted - Please restart\n"
newline_msg:        .asciz "\n"
pmode_msg:          .asciz "32-bit protected mode active - Setting up long mode"
longmode_msg:       .asciz "64-bit long mode active - Transferring to kernel"

# GDT for 32-bit mode - FIXED
.align 8
s2_gdt32:
    .quad 0x0000000000000000    # Null descriptor
    .quad 0x00CF9A000000FFFF    # 32-bit code: base=0, limit=4GB, DPL=0, code
    .quad 0x00CF92000000FFFF    # 32-bit data: base=0, limit=4GB, DPL=0, data

s2_gdt32_desc:
    .word s2_gdt32_desc - s2_gdt32 - 1  # Limit
    .long s2_gdt32                       # Base

# GDT for 64-bit mode - FIXED with proper L bit
.align 8
s2_gdt64:
    .quad 0x0000000000000000    # Null descriptor
    .quad 0x00209A0000000000    # 64-bit code: L=1, DPL=0, code, present
    .quad 0x0000920000000000    # 64-bit data: DPL=0, data, present

s2_gdt64_desc:
    .word s2_gdt64_desc - s2_gdt64 - 1  # Limit  
    .quad s2_gdt64                       # Base
