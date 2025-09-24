// boot/boot.c - UEFI Bootloader for Cinnamon OS
// this will be boot.efi in the actual OS 

#include <efi.h>
#include <efilib.h>

// ACPI table GUIDs (manual definitions for compatibility)
#define ACPI_TABLE_GUID \
  { 0xeb9d2d30, 0x2d88, 0x11d3, {0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d} }

#define ACPI_20_TABLE_GUID \
  { 0x8868e871, 0xe4f1, 0x11d3, {0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81} }

// Boot information structure for kernel handoff
typedef struct {
    void* framebuffer_base;
    UINT32 framebuffer_width;
    UINT32 framebuffer_height;
    UINT32 framebuffer_pitch;
    UINT32 framebuffer_format;
    void* memory_map;
    UINT64 memory_map_size;
    UINT64 memory_map_desc_size;
    UINT32 memory_map_desc_version;
    void* rsdp;              // ACPI Root System Description Pointer
    UINT32 acpi_revision;    // 1 for ACPI 1.0, 2 for ACPI 2.0+
    UINT64 kernel_size;      // Size of loaded kernel
    UINT64 initrd_base;      // Initial RAM disk base
    UINT64 initrd_size;      // Initial RAM disk size
    char cmdline[512];       // Kernel command line
} __attribute__((packed)) BootInfo;

// ELF64 structures for kernel loading
typedef struct {
    unsigned char e_ident[16];
    UINT16 e_type;
    UINT16 e_machine;
    UINT32 e_version;
    UINT64 e_entry;
    UINT64 e_phoff;
    UINT64 e_shoff;
    UINT32 e_flags;
    UINT16 e_ehsize;
    UINT16 e_phentsize;
    UINT16 e_phnum;
    UINT16 e_shentsize;
    UINT16 e_shnum;
    UINT16 e_shstrndx;
} __attribute__((packed)) Elf64_Ehdr;

typedef struct {
    UINT32 p_type;
    UINT32 p_flags;
    UINT64 p_offset;
    UINT64 p_vaddr;
    UINT64 p_paddr;
    UINT64 p_filesz;
    UINT64 p_memsz;
    UINT64 p_align;
} __attribute__((packed)) Elf64_Phdr;

// ELF constants
#define EI_MAG0     0
#define EI_MAG1     1
#define EI_MAG2     2
#define EI_MAG3     3
#define EI_CLASS    4
#define EI_DATA     5
#define ELFMAG0     0x7f
#define ELFMAG1     'E'
#define ELFMAG2     'L'
#define ELFMAG3     'F'
#define ELFCLASS64  2
#define ELFDATA2LSB 1
#define EM_X86_64   62
#define ET_EXEC     2
#define ET_DYN      3
#define PT_LOAD     1

// Pixel format enumeration (matches UEFI GOP values)
#define PIXEL_RGB_RESERVED_8BIT_PER_COLOR    0
#define PIXEL_BGR_RESERVED_8BIT_PER_COLOR    1
#define PIXEL_BITMASK                        2
#define PIXEL_BLT_ONLY                       3
#define PIXEL_UNSUPPORTED                    4

// Global variables
static EFI_HANDLE gImageHandle;
static EFI_SYSTEM_TABLE *ST;
static EFI_BOOT_SERVICES *BS;
static EFI_RUNTIME_SERVICES *RT;

// External assembly function (implemented in arch/x86/entry.S)
extern void jump_to_kernel(UINT64 entry_point, BootInfo* boot_info);

// Print functions for diagnostics
static void print(const CHAR16* str) {
    if (ST && ST->ConOut) {
        ST->ConOut->OutputString(ST->ConOut, (CHAR16*)str);
    }
}

static void print_hex(UINT64 value) {
    CHAR16 buffer[19];
    CHAR16 hex_chars[] = L"0123456789ABCDEF";
    INT32 i;
    
    buffer[0] = L'0';
    buffer[1] = L'x';
    
    for (i = 15; i >= 0; i--) {
        buffer[2 + (15 - i)] = hex_chars[(value >> (i * 4)) & 0xF];
    }
    buffer[18] = 0;
    print(buffer);
}

static void print_uint(UINT64 value) {
    if (value == 0) {
        print(L"0");
        return;
    }
    
    CHAR16 buffer[21] = {0};
    INT32 pos = 19;
    
    while (value > 0 && pos >= 0) {
        buffer[pos--] = L'0' + (value % 10);
        value /= 10;
    }
    
    print(&buffer[pos + 1]);
}

static void print_status(const CHAR16* operation, EFI_STATUS status) {
    print(operation);
    if (EFI_ERROR(status)) {
        print(L" - FAILED (0x");
        print_hex(status);
        print(L")\r\n");
    } else {
        print(L" - OK\r\n");
    }
}

// Print command line helper
static void print_cmdline(const char* cmdline) {
    CHAR16 wchar[2];
    wchar[1] = 0; // Null terminator
    while (*cmdline) {
        wchar[0] = (CHAR16)(*cmdline);
        ST->ConOut->OutputString(ST->ConOut, wchar);
        cmdline++;
    }
}

// Bare panic for post-ExitBootServices emergencies
static void bare_panic(void) {
    asm volatile("cli");
    while(1) { 
        asm volatile("hlt"); 
    }
}

// Critical error handler - NEVER call after ExitBootServices()
static void panic(const CHAR16* message) {
    print(L"\r\n*** CINNAMON OS BOOTLOADER PANIC ***\r\n");
    print(message);
    print(L"\r\nSystem halted. Press any key to reboot.\r\n");
    
    if (ST && ST->ConIn) {
        EFI_INPUT_KEY key;
        while (ST->ConIn->ReadKeyStroke(ST->ConIn, &key) == EFI_NOT_READY) {
            // Wait for key
        }
        if (RT) {
            RT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
        }
    }
    
    bare_panic();
}

// Load file from EFI system partition
static EFI_STATUS load_file(const CHAR16* path, void** buffer, UINTN* size) {
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL *loaded_image = NULL;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *file_system = NULL;
    EFI_FILE_PROTOCOL *root = NULL;
    EFI_FILE_PROTOCOL *file = NULL;
    EFI_FILE_INFO *file_info = NULL;
    UINTN info_size = sizeof(EFI_FILE_INFO) + 1024;
    
    *buffer = NULL;
    *size = 0;
    
    status = BS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (void**)&loaded_image);
    if (EFI_ERROR(status)) {
        return status;
    }
    
    status = BS->HandleProtocol(loaded_image->DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, (void**)&file_system);
    if (EFI_ERROR(status)) {
        return status;
    }
    
    status = file_system->OpenVolume(file_system, &root);
    if (EFI_ERROR(status)) {
        return status;
    }
    
    status = root->Open(root, &file, (CHAR16*)path, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) {
        root->Close(root);
        return status;
    }
    
    status = BS->AllocatePool(EfiLoaderData, info_size, (void**)&file_info);
    if (EFI_ERROR(status)) {
        file->Close(file);
        root->Close(root);
        return status;
    }
    
    status = file->GetInfo(file, &gEfiFileInfoGuid, &info_size, file_info);
    if (EFI_ERROR(status)) {
        BS->FreePool(file_info);
        file->Close(file);
        root->Close(root);
        return status;
    }
    
    if (file_info->FileSize == 0) {
        BS->FreePool(file_info);
        file->Close(file);
        root->Close(root);
        return EFI_BAD_BUFFER_SIZE;
    }
    
    if (file_info->FileSize > 0x40000000ULL) {
        print(L"Warning: Large file size (");
        print_uint(file_info->FileSize);
        print(L" bytes) - may cause issues\r\n");
    }
    
    *size = file_info->FileSize;
    status = BS->AllocatePool(EfiLoaderData, *size, buffer);
    if (EFI_ERROR(status)) {
        BS->FreePool(file_info);
        file->Close(file);
        root->Close(root);
        return status;
    }
    
    UINTN read_size = *size;
    status = file->Read(file, &read_size, *buffer);
    if (EFI_ERROR(status) || read_size != *size) {
        BS->FreePool(file_info);
        BS->FreePool(*buffer);
        *buffer = NULL;
        *size = 0;
        status = EFI_LOAD_ERROR;
    }
    
    BS->FreePool(file_info);
    file->Close(file);
    root->Close(root);
    
    return status;
}

// ELF64 validation
static BOOLEAN validate_elf_header(Elf64_Ehdr* elf_header, UINTN file_size) {
    if (file_size < sizeof(Elf64_Ehdr)) {
        print(L"ELF file too small\r\n");
        return FALSE;
    }
    
    if (elf_header->e_ident[EI_MAG0] != ELFMAG0 ||
        elf_header->e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header->e_ident[EI_MAG2] != ELFMAG2 ||
        elf_header->e_ident[EI_MAG3] != ELFMAG3) {
        print(L"Invalid ELF magic number\r\n");
        return FALSE;
    }
    
    if (elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
        print(L"Not a 64-bit ELF file\r\n");
        return FALSE;
    }
    
    if (elf_header->e_ident[EI_DATA] != ELFDATA2LSB) {
        print(L"Not little-endian ELF file\r\n");
        return FALSE;
    }
    
    if (elf_header->e_machine != EM_X86_64) {
        print(L"Not an x86_64 ELF file\r\n");
        return FALSE;
    }
    
    if (elf_header->e_type != ET_EXEC && elf_header->e_type != ET_DYN) {
        print(L"Not an executable ELF file\r\n");
        return FALSE;
    }
    
    if (elf_header->e_entry == 0 || elf_header->e_entry < 0x100000ULL) {
        print(L"Invalid or low entry point\r\n");
        return FALSE;
    }
    
    if (elf_header->e_phoff == 0 || elf_header->e_phnum == 0) {
        print(L"Missing program header table\r\n");
        return FALSE;
    }
    
    if (elf_header->e_phentsize < sizeof(Elf64_Phdr)) {
        print(L"Invalid program header entry size\r\n");
        return FALSE;
    }
    
    UINTN phdr_table_size = (UINTN)elf_header->e_phnum * elf_header->e_phentsize;
    if (elf_header->e_phoff + phdr_table_size > file_size) {
        print(L"Program header table extends beyond file\r\n");
        return FALSE;
    }
    
    return TRUE;
}

// Load ELF64 kernel with relocation support
static UINT64 load_kernel(void* kernel_data, UINTN kernel_size) {
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)kernel_data;
    Elf64_Phdr* program_headers;
    EFI_STATUS status;
    UINT64 lowest_addr = UINT64_MAX;
    UINT64 highest_addr = 0;
    UINT64 load_base = 0;
    INT32 loadable_segments = 0;
    BOOLEAN is_relocatable = FALSE;
    
    if (!validate_elf_header(elf_header, kernel_size)) {
        panic(L"Kernel ELF validation failed - Invalid format");
    }
    
    if (elf_header->e_type == ET_DYN) {
        is_relocatable = TRUE;
        print(L"ELF64 relocatable kernel detected\r\n");
    } else {
        print(L"ELF64 fixed-address kernel detected\r\n");
    }
    
    print(L"Entry point: ");
    print_hex(elf_header->e_entry);
    print(L"\r\n");
    
    program_headers = (Elf64_Phdr*)((UINT8*)kernel_data + elf_header->e_phoff);
    
    // First pass: validate all segments and calculate memory requirements
    for (UINT16 i = 0; i < elf_header->e_phnum; i++) {
        Elf64_Phdr* phdr = &program_headers[i];
        
        if (phdr->p_type == PT_LOAD) {
            loadable_segments++;
            
            if (phdr->p_offset + phdr->p_filesz > kernel_size) {
                panic(L"Kernel segment extends beyond file boundary");
            }
            
            if (phdr->p_vaddr == 0 || phdr->p_memsz == 0) {
                panic(L"Invalid kernel segment virtual address or size");
            }
            
            if (phdr->p_filesz > phdr->p_memsz) {
                panic(L"Kernel segment file size exceeds memory size");
            }
            
            if (phdr->p_align > 1 && (phdr->p_vaddr % phdr->p_align) != 0) {
                panic(L"Kernel segment not properly aligned");
            }
            
            UINT64 segment_start = phdr->p_vaddr;
            UINT64 segment_end = phdr->p_vaddr + phdr->p_memsz;
            
            if (segment_start < lowest_addr) {
                lowest_addr = segment_start;
            }
            if (segment_end > highest_addr) {
                highest_addr = segment_end;
            }
            
            if (!is_relocatable && (segment_start < 0xFFFFFFFF80000000ULL)) {
                print(L"Warning: Fixed kernel not in higher-half\r\n");
            }
            
            print(L"Segment ");
            print_uint(i);
            print(L": vaddr=");
            print_hex(phdr->p_vaddr);
            print(L" filesz=");
            print_uint(phdr->p_filesz);
            print(L" memsz=");
            print_uint(phdr->p_memsz);
            print(L" flags=");
            print_hex(phdr->p_flags);
            print(L"\r\n");
        }
    }
    
    if (loadable_segments == 0) {
        panic(L"No loadable segments found in kernel ELF");
    }
    
    print(L"Found ");
    print_uint(loadable_segments);
    print(L" loadable segments\r\n");
    print(L"Memory range: ");
    print_hex(lowest_addr);
    print(L" - ");
    print_hex(highest_addr);
    print(L"\r\n");
    
    // Second pass: load segments into memory
    for (UINT16 i = 0; i < elf_header->e_phnum; i++) {
        Elf64_Phdr* phdr = &program_headers[i];
        
        if (phdr->p_type == PT_LOAD) {
            void* segment_data = (void*)((UINT8*)kernel_data + phdr->p_offset);
            EFI_PHYSICAL_ADDRESS segment_addr = (EFI_PHYSICAL_ADDRESS)phdr->p_vaddr;
            UINTN pages = (phdr->p_memsz + 0xFFFULL) >> 12;
            
            print(L"Loading segment ");
            print_uint(i);
            print(L" at ");
            print_hex(phdr->p_vaddr);
            print(L" (");
            print_uint(pages);
            print(L" pages)\r\n");
            
            EFI_PHYSICAL_ADDRESS original_addr = segment_addr;
            status = BS->AllocatePages(AllocateAddress, EfiLoaderData, pages, &segment_addr);
            
            if (EFI_ERROR(status) && is_relocatable) {
                segment_addr = 0;
                status = BS->AllocatePages(AllocateAnyPages, EfiLoaderData, pages, &segment_addr);
                if (!EFI_ERROR(status) && load_base == 0) {
                    load_base = segment_addr - phdr->p_vaddr;
                    print(L"Kernel relocated to base: ");
                    print_hex(load_base);
                    print(L"\r\n");
                }
            }
            
            if (EFI_ERROR(status)) {
                panic(L"Failed to allocate memory for kernel segment");
            }
            
            SetMem((void*)segment_addr, phdr->p_memsz, 0);
            
            if (phdr->p_filesz > 0) {
                CopyMem((void*)segment_addr, segment_data, phdr->p_filesz);
            }
            
            print(L"Segment loaded at ");
            print_hex(segment_addr);
            print(L"\r\n");
        }
    }
    
    return elf_header->e_entry + load_base;
}

// Set up Graphics Output Protocol
static EFI_STATUS setup_graphics(BootInfo* boot_info) {
    EFI_STATUS status;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = NULL;
    UINTN handle_count = 0;
    EFI_HANDLE *handle_buffer = NULL;
    
    boot_info->framebuffer_base = NULL;
    boot_info->framebuffer_width = 0;
    boot_info->framebuffer_height = 0;
    boot_info->framebuffer_pitch = 0;
    boot_info->framebuffer_format = PIXEL_BLT_ONLY;
    
    status = BS->LocateHandleBuffer(ByProtocol, &gEfiGraphicsOutputProtocolGuid, NULL, &handle_count, &handle_buffer);
    if (EFI_ERROR(status) || handle_count == 0) {
        print(L"Warning: No graphics output available - text mode only\r\n");
        return EFI_SUCCESS;
    }
    
    print(L"Found ");
    print_uint(handle_count);
    print(L" graphics device(s)\r\n");
    
    status = BS->HandleProtocol(handle_buffer[0], &gEfiGraphicsOutputProtocolGuid, (void**)&gop);
    if (EFI_ERROR(status)) {
        BS->FreePool(handle_buffer);
        print(L"Warning: Failed to open graphics protocol\r\n");
        return EFI_SUCCESS;
    }
    
    if (!gop->Mode || !gop->Mode->Info || gop->Mode->FrameBufferSize == 0) {
        BS->FreePool(handle_buffer);
        print(L"Warning: Invalid graphics mode\r\n");
        return EFI_SUCCESS;
    }
    
    boot_info->framebuffer_base = (void*)gop->Mode->FrameBufferBase;
    boot_info->framebuffer_width = gop->Mode->Info->HorizontalResolution;
    boot_info->framebuffer_height = gop->Mode->Info->VerticalResolution;
    
    UINT32 bytes_per_pixel = 4;
    switch (gop->Mode->Info->PixelFormat) {
        case PixelRedGreenBlueReserved8BitPerColor:
            boot_info->framebuffer_format = PIXEL_RGB_RESERVED_8BIT_PER_COLOR;
            bytes_per_pixel = 4;
            break;
        case PixelBlueGreenRedReserved8BitPerColor:
            boot_info->framebuffer_format = PIXEL_BGR_RESERVED_8BIT_PER_COLOR;
            bytes_per_pixel = 4;
            break;
        case PixelBitMask:
            boot_info->framebuffer_format = PIXEL_BITMASK;
            // Calculate actual bytes per pixel from bitmasks
            EFI_PIXEL_BITMASK *mask = &gop->Mode->Info->PixelInformation;
            UINT32 total_bits = 0;
            if (mask->RedMask) total_bits = 32 - __builtin_clz(mask->RedMask);
            if (mask->GreenMask) {
                UINT32 green_bits = 32 - __builtin_clz(mask->GreenMask);
                if (green_bits > total_bits) total_bits = green_bits;
            }
            if (mask->BlueMask) {
                UINT32 blue_bits = 32 - __builtin_clz(mask->BlueMask);
                if (blue_bits > total_bits) total_bits = blue_bits;
            }
            bytes_per_pixel = (total_bits + 7) / 8;
            if (bytes_per_pixel < 2) bytes_per_pixel = 2;
            if (bytes_per_pixel == 3) bytes_per_pixel = 4;
            break;
        case PixelBltOnly:
            boot_info->framebuffer_format = PIXEL_BLT_ONLY;
            bytes_per_pixel = 4;
            break;
        default:
            boot_info->framebuffer_format = PIXEL_UNSUPPORTED;
            print(L"Warning: Unsupported pixel format - using software BLT fallback\r\n");
            bytes_per_pixel = 4;
            break;
    }
    
    boot_info->framebuffer_pitch = gop->Mode->Info->PixelsPerScanLine * bytes_per_pixel;
    
    if (boot_info->framebuffer_width == 0 || boot_info->framebuffer_height == 0) {
        print(L"Warning: Invalid framebuffer dimensions\r\n");
        boot_info->framebuffer_base = NULL;
    } else {
        print(L"Framebuffer: ");
        print_hex((UINT64)boot_info->framebuffer_base);
        print(L" (");
        print_uint(boot_info->framebuffer_width);
        print(L"x");
        print_uint(boot_info->framebuffer_height);
        print(L", pitch=");
        print_uint(boot_info->framebuffer_pitch);
        print(L", bpp=");
        print_uint(bytes_per_pixel);
        print(L")\r\n");
    }
    
    BS->FreePool(handle_buffer);
    return EFI_SUCCESS;
}

// Find ACPI RSDP with validation
static void* find_rsdp(BootInfo* boot_info) {
    EFI_CONFIGURATION_TABLE *config_table;
    EFI_GUID acpi_20_table_guid = ACPI_20_TABLE_GUID;
    EFI_GUID acpi_table_guid = ACPI_TABLE_GUID;
    void* rsdp_table = NULL;
    
    if (!ST || !ST->ConfigurationTable) {
        return NULL;
    }
    
    config_table = ST->ConfigurationTable;
    
    // Try ACPI 2.0+ first
    for (UINTN i = 0; i < ST->NumberOfTableEntries; i++) {
        if (CompareGuid(&config_table[i].VendorGuid, &acpi_20_table_guid)) {
            rsdp_table = config_table[i].VendorTable;
            boot_info->acpi_revision = 2;
            break;
        }
    }
    
    // Fall back to ACPI 1.0
    if (!rsdp_table) {
        for (UINTN i = 0; i < ST->NumberOfTableEntries; i++) {
            if (CompareGuid(&config_table[i].VendorGuid, &acpi_table_guid)) {
                rsdp_table = config_table[i].VendorTable;
                boot_info->acpi_revision = 1;
                break;
            }
        }
    }
    
    // Validate RSDP signature if found
    if (rsdp_table) {
        char* signature = (char*)rsdp_table;
        if (signature[0] == 'R' && signature[1] == 'S' && signature[2] == 'D' && 
            signature[3] == ' ' && signature[4] == 'P' && signature[5] == 'T' && 
            signature[6] == 'R' && signature[7] == ' ') {
            return rsdp_table;
        } else {
            print(L"Warning: Invalid RSDP signature\r\n");
            return NULL;
        }
    }
    
    return NULL;
}

// Get UEFI memory map and exit boot services
static EFI_STATUS get_memory_map_and_exit_boot_services(BootInfo* boot_info) {
    EFI_STATUS status;
    UINTN map_size = 0;
    UINTN map_key = 0;
    UINTN desc_size = 0;
    UINT32 desc_version = 0;
    void* memory_map = NULL;
    INT32 retry_count = 0;
    const INT32 max_retries = 10;
    
    status = BS->GetMemoryMap(&map_size, NULL, &map_key, &desc_size, &desc_version);
    if (status != EFI_BUFFER_TOO_SMALL) {
        return status;
    }
    
    map_size += 16 * desc_size;
    
    print(L"Memory map size: ");
    print_uint(map_size);
    print(L" bytes\r\n");
    
    while (retry_count < max_retries) {
        if (memory_map != NULL) {
            BS->FreePool(memory_map);
            memory_map = NULL;
        }
        
        status = BS->AllocatePool(EfiLoaderData, map_size, &memory_map);
        if (EFI_ERROR(status)) {
            print(L"Failed to allocate memory map buffer\r\n");
            return status;
        }
        
        UINTN actual_map_size = map_size;
        status = BS->GetMemoryMap(&actual_map_size, memory_map, &map_key, &desc_size, &desc_version);
        if (EFI_ERROR(status)) {
            if (status == EFI_BUFFER_TOO_SMALL) {
                map_size = actual_map_size * 2;
                retry_count++;
                print(L"Buffer too small, retrying with larger size...\r\n");
                continue;
            } else {
                BS->FreePool(memory_map);
                return status;
            }
        }
        
        boot_info->memory_map = memory_map;
        boot_info->memory_map_size = actual_map_size;
        boot_info->memory_map_desc_size = desc_size;
        boot_info->memory_map_desc_version = desc_version;
        
        print(L"Attempting to exit boot services (attempt ");
        print_uint(retry_count + 1);
        print(L")...\r\n");
        
        status = BS->ExitBootServices(gImageHandle, map_key);
        if (!EFI_ERROR(status)) {
            return EFI_SUCCESS;
        }
        
        retry_count++;
        print(L"Memory map changed, retrying...\r\n");
    }
    
    if (memory_map != NULL) {
        BS->FreePool(memory_map);
    }
    
    return EFI_LOAD_ERROR;
}

// Safe string copy with bounds checking
static void safe_strcpy(char* dest, const char* src, UINTN dest_size) {
    if (dest_size == 0) return;
    
    UINTN i = 0;
    while (i < dest_size - 1 && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

// Main UEFI bootloader entry point
EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    EFI_STATUS status;
    void* kernel_data = NULL;
    UINTN kernel_size = 0;
    void* initrd_data = NULL;
    UINTN initrd_size = 0;
    UINT64 kernel_entry_point = 0;
    BootInfo boot_info = {0};
    
    // Initialize global variables
    gImageHandle = ImageHandle;
    ST = SystemTable;
    BS = SystemTable->BootServices;
    RT = SystemTable->RuntimeServices;
    
    // Validate UEFI system table
    if (!ST || !BS || !RT || !ST->ConOut) {
        return EFI_LOAD_ERROR;
    }
    
    // Clear screen and display banner
    ST->ConOut->ClearScreen(ST->ConOut);
    ST->ConOut->SetAttribute(ST->ConOut, EFI_LIGHTCYAN | EFI_BACKGROUND_BLACK);
    
    print(L"+==============================================================================+\r\n");
    print(L"|                       Cinnamon OS UEFI Bootloader                           |\r\n");
    print(L"|                            x86_64 Boot System                               |\r\n");
    print(L"+==============================================================================+\r\n\r\n");
    
    ST->ConOut->SetAttribute(ST->ConOut, EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK);
    
    // Display system information
    print(L"UEFI Version: ");
    print_uint((ST->Hdr.Revision >> 16));
    print(L".");
    print_uint(ST->Hdr.Revision & 0xFFFF);
    print(L"\r\nSystem Table: ");
    print_hex((UINT64)ST);
    print(L"\r\n\r\n");
    
    // Load kernel
    print(L"[1/7] Loading Cinnamon OS kernel...\r\n");
    status = load_file(L"\\EFI\\CinnamonOS\\kernel.elf", &kernel_data, &kernel_size);
    if (EFI_ERROR(status)) {
        panic(L"CRITICAL: Cannot load kernel.elf from ESP");
    }
    print_status(L"Kernel file loading", status);
    print(L"Kernel size: ");
    print_uint(kernel_size);
    print(L" bytes\r\n\r\n");
    
    // Load initial RAM disk (optional)
    print(L"[2/7] Loading initial RAM disk...\r\n");
    status = load_file(L"\\EFI\\CinnamonOS\\initrd.img", &initrd_data, &initrd_size);
    if (EFI_ERROR(status)) {
        print(L"  No initrd found, continuing without initial RAM disk\r\n");
        boot_info.initrd_base = 0;
        boot_info.initrd_size = 0;
    } else {
        boot_info.initrd_base = (UINT64)initrd_data;
        boot_info.initrd_size = initrd_size;
        print(L"Initrd loaded: ");
        print_uint(initrd_size);
        print(L" bytes\r\n");
    }
    print(L"\r\n");
    
    // Parse and load ELF kernel
    print(L"[3/7] Parsing ELF64 kernel and loading segments...\r\n");
    kernel_entry_point = load_kernel(kernel_data, kernel_size);
    boot_info.kernel_size = kernel_size;
    print(L"Kernel loaded successfully, entry point: ");
    print_hex(kernel_entry_point);
    print(L"\r\n\r\n");
    
    // Set up graphics output
    print(L"[4/7] Initializing graphics subsystem...\r\n");
    status = setup_graphics(&boot_info);
    print_status(L"Graphics initialization", status);
    print(L"\r\n");
    
    // Find ACPI tables
    print(L"[5/7] Locating ACPI tables...\r\n");
    boot_info.rsdp = find_rsdp(&boot_info);
    if (boot_info.rsdp) {
        print(L"ACPI RSDP found at: ");
        print_hex((UINT64)boot_info.rsdp);
        print(L" (revision ");
        print_uint(boot_info.acpi_revision);
        print(L")\r\n");
    } else {
        print(L"ACPI RSDP not found - system may have limited functionality\r\n");
        boot_info.acpi_revision = 0;
    }
    print(L"\r\n");
    
    // Set up kernel command line with bounds checking
    print(L"[6/7] Setting up kernel command line...\r\n");
    safe_strcpy(boot_info.cmdline, "root=/dev/sda1 quiet splash loglevel=3", sizeof(boot_info.cmdline));
    print(L"Command line: ");
    print_cmdline(boot_info.cmdline);
    print(L"\r\n\r\n");
    
    // Final preparations - point of no return approaching
    print(L"[7/7] Final boot preparations...\r\n");
    print(L"Preparing to exit UEFI boot services...\r\n");
    print(L"After this point, UEFI console will be unavailable\r\n");
    
    // Get memory map and exit boot services - CRITICAL SECTION
    status = get_memory_map_and_exit_boot_services(&boot_info);
    if (EFI_ERROR(status)) {
        panic(L"CRITICAL: Failed to exit UEFI boot services - Cannot proceed");
    }
    
    // ============================================================================
    // POINT OF NO RETURN: Boot services are now terminated
    // NO MORE UEFI FUNCTION CALLS ALLOWED BEYOND THIS POINT
    // Console output, memory allocation, and all UEFI services are unavailable
    // ============================================================================
    
    // Final validation before kernel transfer
    if (kernel_entry_point == 0 || boot_info.memory_map == NULL) {
        bare_panic();
    }
    
    // Transfer control to kernel with boot information
    // The jump_to_kernel function (in arch/x86/entry.S) will:
    // 1. Ensure 16-byte stack alignment (CRITICAL for SSE instructions)
    // 2. Put BootInfo* pointer in RDI register (System V ABI)
    // 3. Clear other registers for clean state
    // 4. Jump to kernel entry point
    // 5. Kernel entry.S will then jump to kernel_main() in init/main.c
    jump_to_kernel(kernel_entry_point, &boot_info);
    
    // Should absolutely never reach this point
    // If we do, something catastrophic happened during kernel transfer
    bare_panic();
    
    return EFI_LOAD_ERROR; // Never reached
}
