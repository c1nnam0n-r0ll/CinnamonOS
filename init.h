// kernel/include/init.h

#ifndef _INIT_H
#define _INIT_H

#include <types.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Kernel version information
#define CINNAMON_VERSION_MAJOR  0
#define CINNAMON_VERSION_MINOR  1
#define CINNAMON_VERSION_PATCH  0

// Build configuration defaults
#ifndef CONFIG_MAX_CPUS
#define CONFIG_MAX_CPUS 64
#endif

#ifndef CONFIG_AP_BOOT_TIMEOUT_MS
#define CONFIG_AP_BOOT_TIMEOUT_MS 3000
#endif

#ifndef CONFIG_AP_BOOT_RETRIES
#define CONFIG_AP_BOOT_RETRIES 1
#endif

// Kernel log levels
#define KERN_PANIC  "[PANIC] "
#define KERN_ERROR  "[ERROR] "
#define KERN_WARN   "[WARN]  "
#define KERN_INFO   "[INFO]  "
#define KERN_OK     "[OK]    "
#define KERN_DEBUG  "[DEBUG] "
#define KERN_NONE   ""

// Boot information structure passed from UEFI bootloader
typedef struct {
    // Memory map information
    uint64_t memory_map_size;
    uint64_t memory_map_key;
    uint64_t descriptor_size;
    uint32_t descriptor_version;
    void    *memory_map;
    
    // Framebuffer information
    uint64_t framebuffer_base;
    uint64_t framebuffer_size;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint32_t framebuffer_pitch;
    
    // ACPI and initial ramdisk
    uint64_t rsdp_address;      // ACPI Root System Description Pointer
    uint64_t initrd_base;       // Initial RAM disk base address
    uint64_t initrd_size;       // Initial RAM disk size
    
    // Kernel command line (255 chars + null terminator)
    char     cmdline[256];
} __attribute__((packed)) BootInfo;

// Subsystem status bit definitions
enum {
    SUBSYS_MEMORY_BIT = 0,
    SUBSYS_INTERRUPTS_BIT,
    SUBSYS_TIMING_BIT,
    SUBSYS_SCHEDULER_BIT,
    SUBSYS_PROCESS_BIT,
    SUBSYS_IPC_BIT,
    SUBSYS_SYSCALLS_BIT,
    SUBSYS_NETWORK_BIT,
    SUBSYS_SMP_BIT,
    SUBSYS_ACPI_BIT
};

// Panic severity levels
#define PANIC_CRITICAL  0
#define PANIC_SEVERE    1
#define PANIC_MODERATE  2

// Recovery system constants
#define RECOVERY_MAGIC 0xDEADBEEF
#define RECOVERY_VERSION 1
#define RECOVERY_HANDOFF_ADDR 0x9000
#define RECOVERY_SIGNATURE_ADDR 0x8F00
#define RECOVERY_SIGNATURE_MAGIC 0xC1AE4302
#define RECOVERY_TEST_ADDR 0x9F00

// Recovery signature structure
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t entry_point;
    uint32_t checksum;
} recovery_signature_t;

// Recovery handoff structure
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t panic_time;
    uint32_t panic_level;
    uint32_t cpu_id;
    char panic_message[512];
    uint64_t stack_trace[16];
    uint64_t memory_map_addr;
    uint64_t framebuffer_addr;
    uint32_t fb_width;
    uint32_t fb_height;
    uint32_t fb_pitch;
} recovery_handoff_t;

// ============================================================================
// MAIN KERNEL ENTRY POINT
// ============================================================================

// Main kernel entry point called from assembly
void kernel_main(BootInfo *boot_info) __attribute__((noreturn));

// ============================================================================
// KERNEL STATE QUERY FUNCTIONS
// ============================================================================

// Check if kernel initialization is complete
bool is_kernel_initialized(void);

// Get kernel uptime in milliseconds
uint64_t get_kernel_uptime(void);

// Get boot information structure
BootInfo *get_boot_info(void);

// Check if a specific subsystem is available
bool is_subsystem_available(int subsystem_bit);

// ============================================================================
// PANIC AND ERROR HANDLING
// ============================================================================

// Critical panic - system cannot continue
void panic(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));

// Panic with severity level
void kernel_panic_level(int level, const char *fmt, ...) 
    __attribute__((noreturn, format(printf, 2, 3)));

// Non-fatal kernel warning
void kernel_warning(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// Get panic statistics
uint32_t get_panic_count(void);
const char *get_last_panic_message(void);
uint64_t get_last_panic_time(void);
bool is_system_panicking(void);

// Reset panic state (for recovery/testing)
void reset_panic_state(void);

// Store panic information to persistent storage
void store_panic_to_disk(void);

// ============================================================================
// EMERGENCY OUTPUT FUNCTIONS
// ============================================================================

// Initialize emergency serial console
void init_emergency_serial(void);

// Emergency serial output (always works)
void emergency_serial_print(const char *str);

// Initialize serial console
void init_serial_console(void);

// Initialize emergency output (framebuffer or serial)
int init_emergency_output(void);

// ============================================================================
// UTILITY MACROS
// ============================================================================

// Time conversion with proper rounding
#define NS_TO_MS(ns) (((ns) + 500000UL) / 1000000UL)
#define NS_TO_US(ns) (((ns) + 500UL) / 1000UL)
#define MS_TO_NS(ms) ((ms) * 1000000UL)
#define US_TO_NS(us) ((us) * 1000UL)

// Page alignment check
#define IS_PAGE_ALIGNED(addr) (((addr) & 0xFFF) == 0)
#define PAGE_ALIGN_DOWN(addr) ((addr) & ~0xFFFULL)
#define PAGE_ALIGN_UP(addr) (((addr) + 0xFFF) & ~0xFFFULL)

// Debug printing (compiled out in release builds)
#if defined(CONFIG_DEBUG) && !defined(NDEBUG)
#define DEBUG_PRINT(fmt, ...) printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) do { } while (0)
#endif

// ============================================================================
// ATOMIC SUBSYSTEM STATUS OPERATIONS
// ============================================================================

// Set a subsystem status bit (SMP-safe)
#define SUBSYS_SET(bit) \
    (__atomic_or_fetch(&subsystem_status, (1U << (bit)), __ATOMIC_SEQ_CST))

// Check if a subsystem status bit is set (SMP-safe)
#define SUBSYS_IS_SET(bit) \
    (__atomic_load_n(&subsystem_status, __ATOMIC_SEQ_CST) & (1U << (bit)))

// Clear a subsystem status bit (SMP-safe)
#define SUBSYS_CLEAR(bit) \
    (__atomic_and_fetch(&subsystem_status, ~(1U << (bit)), __ATOMIC_SEQ_CST))

// ============================================================================
// COMPILER ATTRIBUTES
// ============================================================================

// Mark function as weak symbol (can be overridden)
#define __weak __attribute__((weak))

// Mark function as constructor (runs before main)
#define __init __attribute__((constructor))

// Mark function as destructor (runs after main)
#define __exit __attribute__((destructor))

// Mark data as section-specific
#define __section(name) __attribute__((section(name)))

// Mark as always inline
#define __always_inline inline __attribute__((always_inline))

// Mark as never inline
#define __noinline __attribute__((noinline))

// ============================================================================
// BUILD DATE AND VERSION STRINGS
// ============================================================================

// Build date and time (provided by compiler)
#define CINNAMON_BUILD_DATE __DATE__
#define CINNAMON_BUILD_TIME __TIME__

// Version string
#define CINNAMON_VERSION_STRING \
    _STRINGIFY(CINNAMON_VERSION_MAJOR) "." \
    _STRINGIFY(CINNAMON_VERSION_MINOR) "." \
    _STRINGIFY(CINNAMON_VERSION_PATCH)

#define _STRINGIFY(x) #x

// ============================================================================
// LINKER SYMBOLS
// ============================================================================

// Kernel image boundaries (defined by linker script)
extern char kernel_start;
extern char kernel_end;
extern char kernel_text_start;
extern char kernel_text_end;
extern char kernel_data_start;
extern char kernel_data_end;
extern char kernel_bss_start;
extern char kernel_bss_end;

// Boot page tables (from bootloader/early assembly)
extern uint64_t boot_pml4;
extern uint64_t boot_pdpt;
extern uint64_t boot_pd;

// ============================================================================
// WEAK SYMBOLS FOR OPTIONAL FEATURES
// ============================================================================

// Security stub for systems without security subsystem
void security_init_stub(void) __weak;

// Network feature disable for systems without network support
void disable_network_features(void) __weak;

#endif // _INIT_H
