// init/main.c

#include <init.h>
#include <mm.h>
#include <sched.h>
#include <proc.h>
#include <ipc.h>
#include <irq.h>
#include <syscall.h>
#include <console.h>
#include <printk.h>
#include <time.h>
#include <net.h>
#include <security.h>
#include <types.h>
#include <stdarg.h>
#include <string.h>

// Kernel log levels - define them here since they're used throughout
#define KERN_PANIC  "[PANIC] "
#define KERN_ERROR  "[ERROR] "
#define KERN_WARN   "[WARN]  "
#define KERN_INFO   "[INFO]  "
#define KERN_OK     "[OK]    "
#define KERN_DEBUG  "[DEBUG] "
#define KERN_NONE   ""

// External symbols from bootloader and assembly - corrected types
extern uint64_t boot_pml4;  // Physical addresses, not pointers
extern uint64_t boot_pdpt; 
extern uint64_t boot_pd;

// Boot information structure passed from UEFI bootloader
typedef struct {
    uint64_t memory_map_size;
    uint64_t memory_map_key;
    uint64_t descriptor_size;
    uint32_t descriptor_version;
    void    *memory_map;
    
    uint64_t framebuffer_base;
    uint64_t framebuffer_size;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint32_t framebuffer_pitch;
    
    uint64_t rsdp_address;      // ACPI Root System Description Pointer
    uint64_t initrd_base;       // Initial RAM disk
    uint64_t initrd_size;
    
    char     cmdline[256];      // Kernel command line
} __attribute__((packed)) BootInfo;  // Must match UEFI bootloader layout

// Debug macro that can be compiled out for release builds
#if defined(CONFIG_DEBUG) && !defined(NDEBUG)
#define DEBUG_PRINT(fmt, ...) printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) do { } while (0)
#endif

// Time conversion with proper rounding
#define NS_TO_MS(ns) (((ns) + 500000UL) / 1000000UL)
#define NS_TO_US(ns) (((ns) + 500UL) / 1000UL)
#define CINNAMON_VERSION_MAJOR  0
#define CINNAMON_VERSION_MINOR  1
#define CINNAMON_VERSION_PATCH  0
#define CINNAMON_BUILD_DATE     __DATE__
#define CINNAMON_BUILD_TIME     __TIME__

// Page alignment check
#define IS_PAGE_ALIGNED(addr) (((addr) & 0xFFF) == 0)

// AP boot timeout increased for slower systems
#ifndef CONFIG_AP_BOOT_TIMEOUT_MS
#define CONFIG_AP_BOOT_TIMEOUT_MS 3000  // 3 seconds per CPU
#endif

#ifndef CONFIG_AP_BOOT_RETRIES
#define CONFIG_AP_BOOT_RETRIES 1
#endif

// Global kernel state
static BootInfo *g_boot_info = NULL;
static volatile bool kernel_initialized = false;
static uint64_t kernel_boot_start_time = 0;  // Boot start time
static uint64_t kernel_ready_time = 0;       // When fully initialized
static uint64_t phase_times[5] = {0};        // All 5 phases recorded
static volatile uint32_t subsystem_status = 0;  // Bitfield for atomic SMP access
static volatile uint32_t cpu_count = 1;     // Number of CPUs detected
static volatile uint32_t cpus_online = 0;   // Number of CPUs currently online

// Per-phase error tracking for post-mortem debugging
typedef struct {
    int error_code;
    const char *subsystem_name;
    const char *error_message;
    uint64_t timestamp;
} phase_error_t;

static phase_error_t phase_errors[16] = {0};  // Track up to 16 errors
static volatile uint32_t error_count = 0;

// Subsystem status bit definitions for SMP-safe access
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

#define SUBSYS_SET(bit) (__atomic_or_fetch(&subsystem_status, (1U << (bit)), __ATOMIC_SEQ_CST))
#define SUBSYS_IS_SET(bit) (__atomic_load_n(&subsystem_status, __ATOMIC_SEQ_CST) & (1U << (bit)))

// Forward declarations for all required external functions
// Console and output functions
int console_init(uint64_t fb_base, uint32_t width, uint32_t height, uint32_t pitch);
void console_clear(void);
int printk_init(void);
int printk(const char *fmt, ...);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);

// Memory management functions with validation
int page_alloc_init(void *memory_map, uint64_t map_size, uint64_t descriptor_size);
int vmem_init(uint64_t pml4, uint64_t pdpt, uint64_t pd);
int kmalloc_init(void);
int paging_init(void);

// Interrupt handling functions
int irq_init(void);
int pic_init(void);
int isr_init(void);

// Scheduler and process functions with proper error checking
int scheduler_init(void);
int thread_init(void);
int process_init(void);
int exec_init(void);
void scheduler_start(void) __attribute__((noreturn));
bool scheduler_has_runnable_tasks(void);
void scheduler_yield(void);
int thread_create_kernel(void (*func)(void), void *arg, const char *name);
pid_t process_create_user(const char *path, const char *cmdline);

// IPC functions  
int ipc_init(void);
int msgqueue_init(void);
int pipe_init(void);
int shm_init(void);

// System call functions
int syscall_init(void);
int syscall_table_init(void);

// Timing functions - must handle early calls gracefully
int timer_init(void);
int rtc_init(void);
uint64_t get_system_time(void); // Must work even before timer_init()

// Network functions
int net_init(void);
int socket_init(void);
void socket_init_stub(void);
int ip_init(void);
int tcp_init(void);
int udp_init(void);

// Security functions
int security_init(void);
int integrity_init(void);
int sandbox_init(void);

// Subsystem failure handling functions
void disable_network_features(void);
bool are_interrupts_enabled(void);
void disable_interrupts(void);
void enable_interrupts(void);
void init_serial_console(void);
int init_emergency_output(void);
void init_emergency_serial(void);
void emergency_serial_print(const char *str);
bool cpu_has_monitor_mwait(void);
void cpu_pause(void);

// SMP and ACPI functions
int acpi_init(void);
uint32_t acpi_get_processor_count(void);
int percpu_init(uint32_t cpu_count);
int percpu_validate_all(void);
int scheduler_init_smp(uint32_t cpu_count);
int smp_boot_cpu(uint32_t cpu_id);
bool is_cpu_online(uint32_t cpu_id);
void mark_cpu_offline(uint32_t cpu_id);
void cpu_relax(void);
void memory_barrier(void);
int validate_scheduler_smp_state(void);
void scheduler_update_cpu_count(uint32_t count);

// String and memory functions (if not provided by standard library)
size_t strnlen(const char *s, size_t maxlen);
void *memset(void *s, int c, size_t n);

// Forward declarations for initialization functions
static void print_banner(void);
static void validate_boot_info(BootInfo *boot_info);
static void validate_framebuffer(BootInfo *boot_info);
static void validate_memory_regions(BootInfo *boot_info);
static void init_early_console(BootInfo *boot_info);
static int  init_memory_management(BootInfo *boot_info);
static int  init_interrupt_handling(void);
static int  init_scheduling(void);
static int  init_process_management(void);
static int  init_ipc_subsystem(void);
static int  init_system_calls(void);
static int  init_timing(void);
static int  init_networking(void);
static int  init_security(void);
static void launch_init_process(void);
static void kernel_idle_task(void);
static void print_subsystem_status(void);
static int  init_smp(void);
static void start_application_processors(void);
static void record_phase_error(const char *subsystem, int error_code, const char *message);
static void emergency_panic(const char *fmt, ...) __attribute__((noreturn));
static void log_memory_map(BootInfo *boot_info);

// Forward declaration for panic function (implemented elsewhere)
void panic(const char *fmt, ...) __attribute__((noreturn));

// Main kernel entry point called from assembly
void kernel_main(BootInfo *boot_info)
{
    int result;
    
    // Validate critical functions exist at compile time
    validate_critical_functions();
    
    // Record boot start time - handle case where timer not yet initialized
    kernel_boot_start_time = get_system_time();
    if (kernel_boot_start_time == 0) {
        // Timer subsystem may not be ready - use a placeholder
        kernel_boot_start_time = 1;  // Non-zero to indicate boot started
    }
    
    // Store boot info globally
    g_boot_info = boot_info;
    
    // Validate boot information before proceeding
    validate_boot_info(boot_info);
    
    // Initialize early console for debugging output
    // Try to initialize console - if this fails, we're in deep trouble
    if (boot_info->framebuffer_base != 0) {
        init_early_console(boot_info);
    } else {
        // No framebuffer available - try serial console fallback
        init_serial_console();
    }
    
    // Print kernel banner
    print_banner();
    
    printk(KERN_INFO "CinnamonOS kernel starting...\n");
    printk(KERN_INFO "Boot info at 0x%lx\n", (uint64_t)boot_info);
    

    // Phase 1: Core kernel subsystems
    printk(KERN_INFO "Phase 1: Initializing core subsystems...\n");
    uint64_t phase1_start = get_system_time();
    
    // Initialize memory management first - everything depends on this
    result = init_memory_management(boot_info);
    if (result != 0) {
        record_phase_error("Memory Management", result, "Failed to initialize memory subsystem");
        emergency_panic("Failed to initialize memory management: %d", result);
    }
    SUBSYS_SET(SUBSYS_MEMORY_BIT);
    printk(KERN_OK "Memory management initialized\n");
    
    // Set up proper interrupt and exception handling
    result = init_interrupt_handling();
    if (result != 0) {
        record_phase_error("Interrupt Handling", result, "Failed to initialize interrupt subsystem");
        emergency_panic("Failed to initialize interrupt handling: %d", result);
    }
    SUBSYS_SET(SUBSYS_INTERRUPTS_BIT);
    printk(KERN_OK "Interrupt handling initialized\n");
    
    // Initialize timing subsystem
    result = init_timing();
    if (result != 0) {
        record_phase_error("Timing", result, "Failed to initialize timing subsystem");
        emergency_panic("Failed to initialize timing: %d", result);
    }
    SUBSYS_SET(SUBSYS_TIMING_BIT);
    printk(KERN_OK "Timing subsystem initialized\n");
    
    // Initialize SMP support after basic subsystems are ready
    result = init_smp();
    if (result != 0) {
        record_phase_error("SMP", result, "SMP initialization failed");
        printk(KERN_WARN "SMP initialization failed: %d (running single-core)\n", result);
    } else {
        SUBSYS_SET(SUBSYS_SMP_BIT);
        printk(KERN_OK "SMP support initialized (%u CPUs detected)\n", cpu_count);
    }
    
    phase_times[0] = get_system_time() - phase1_start;
    printk(KERN_INFO "Phase 1 complete in %lu ms\n", NS_TO_MS(phase_times[0]));
    

    // Phase 2: Process and scheduling subsystems
    printk(KERN_INFO "Phase 2: Initializing process management...\n");
    uint64_t phase2_start = get_system_time();
    
    // Set up task scheduling
    result = init_scheduling();
    if (result != 0) {
        record_phase_error("Scheduler", result, "Failed to initialize scheduler");
        emergency_panic("Failed to initialize scheduler: %d", result);
    }
    SUBSYS_SET(SUBSYS_SCHEDULER_BIT);
    printk(KERN_OK "Scheduler initialized\n");
    
    // Initialize process management
    result = init_process_management();
    if (result != 0) {
        record_phase_error("Process Management", result, "Failed to initialize process subsystem");
        emergency_panic("Failed to initialize process management: %d", result);
    }
    SUBSYS_SET(SUBSYS_PROCESS_BIT);
    printk(KERN_OK "Process management initialized\n");
    
    // Set up IPC mechanisms
    result = init_ipc_subsystem();
    if (result != 0) {
        record_phase_error("IPC", result, "Failed to initialize IPC subsystem");
        emergency_panic("Failed to initialize IPC: %d", result);
    }
    SUBSYS_SET(SUBSYS_IPC_BIT);
    printk(KERN_OK "IPC subsystem initialized\n");
    
    phase_times[1] = get_system_time() - phase2_start;
    printk(KERN_INFO "Phase 2 complete in %lu ms\n", NS_TO_MS(phase_times[1]));
    
    
    // Phase 3: System call interface
    printk(KERN_INFO "Phase 3: Initializing system call interface...\n");
    uint64_t phase3_start = get_system_time();
    
    result = init_system_calls();
    if (result != 0) {
        record_phase_error("System Calls", result, "Failed to initialize system call interface");
        emergency_panic("Failed to initialize system calls: %d", result);
    }
    SUBSYS_SET(SUBSYS_SYSCALLS_BIT);
    printk(KERN_OK "System calls initialized\n");
    
    phase_times[2] = get_system_time() - phase3_start;
    printk(KERN_INFO "Phase 3 complete in %lu ms\n", NS_TO_MS(phase_times[2]));
    
    
    // Phase 4: Optional subsystems
    printk(KERN_INFO "Phase 4: Initializing optional subsystems...\n");
    uint64_t phase4_start = get_system_time();
    
    // Initialize networking stack 
    result = init_networking();
    if (result != 0) {
        record_phase_error("Networking", result, "Networking initialization failed");
        printk(KERN_WARN "Networking initialization failed: %d (system will run without network support)\n", result);
        // Disable any network-dependent features
        disable_network_features();
    } else {
        SUBSYS_SET(SUBSYS_NETWORK_BIT);
        printk(KERN_OK "Network stack initialized\n");
    }
    
    // Initialize security subsystem
    result = init_security();
    if (result != 0) {
        record_phase_error("Security", result, "Security initialization failed");
        // Security failure in production systems should be fatal
#ifdef CONFIG_DEBUG
        printk(KERN_WARN "Security initialization failed: %d - running with stub security\n", result);
        security_init_stub(); // Now safe to call - weak symbol provides default
#else
        emergency_panic("Security initialization failed: %d - cannot run with compromised security", result);
#endif
    } else {
        printk(KERN_OK "Security subsystem initialized\n");
    }
    
    phase_times[3] = get_system_time() - phase4_start;
    printk(KERN_INFO "Phase 4 complete in %lu ms\n", NS_TO_MS(phase_times[3]));
    
    
    // Phase 5: Enable interrupts and launch userspace
    printk(KERN_INFO "Phase 5: Finalizing kernel startup...\n");
    uint64_t phase5_start = get_system_time();
    
    // Record initialization completion time
    kernel_ready_time = get_system_time();
    __atomic_store_n(&kernel_initialized, true, __ATOMIC_SEQ_CST);
    
    // Calculate actual total init time
    uint64_t total_init_time = kernel_ready_time - kernel_boot_start_time;
    printk(KERN_OK "Kernel initialization complete in %lu ms\n",
           NS_TO_MS(total_init_time));
    
    // Print detailed timing breakdown
    printk(KERN_INFO "Phase timing - 1: %lu ms, 2: %lu ms, 3: %lu ms, 4: %lu ms\n",
           NS_TO_MS(phase_times[0]), NS_TO_MS(phase_times[1]),
           NS_TO_MS(phase_times[2]), NS_TO_MS(phase_times[3]));
    
    // Print subsystem status
    print_subsystem_status();
    
    // Start application processors if SMP is available
    if (SUBSYS_IS_SET(SUBSYS_SMP_BIT) && cpu_count > 1) {
        printk(KERN_INFO "Starting %u application processors...\n", cpu_count - 1);
        start_application_processors();
    }
    
    // Enable interrupts with memory barrier - only do this once
    printk(KERN_INFO "Enabling interrupts...\n");
    enable_interrupts();
    
    // Launch the first userspace process (/user/init)
    launch_init_process();
    
    // Record Phase 5 completion
    phase_times[4] = get_system_time() - phase5_start;
    printk(KERN_INFO "Phase 5 complete in %lu ms\n", NS_TO_MS(phase_times[4]));
    
    // We should never reach here, the init process takes over
    emergency_panic("kernel_main() returned - init process failed to start");
}

// Print the kernel startup banner
static void print_banner(void)
{
    console_clear();
    
    printk(KERN_NONE "  ____ _                                          ___  ____  \n");
    printk(KERN_NONE " / ___(_)_ __  _ __   __ _ _ __ ___   ___  _ __  / _ \\/ ___|  \n");
    printk(KERN_NONE "| |   | | '_ \\| '_ \\ / _` | '_ ` _ \\ / _ \\| '_ \\| | | \\___ \\ \n");
    printk(KERN_NONE "| |___| | | | | | | | (_| | | | | | | (_) | | | | |_| |___) | \n");
    printk(KERN_NONE "  \\____|_|_| |_|_| |_|\\__,_|_| |_| |_|\\___/|_| |_|\\___/|____/  \n");
    printk(KERN_NONE "\n");
    printk(KERN_NONE "CinnamonOS v%d.%d.%d - Built %s %s\n", 
           CINNAMON_VERSION_MAJOR, CINNAMON_VERSION_MINOR, 
           CINNAMON_VERSION_PATCH, CINNAMON_BUILD_DATE, CINNAMON_BUILD_TIME);
    printk(KERN_NONE "Open Source Microkernel Operating System\n\n");
}

// Print subsystem initialization status
static void print_subsystem_status(void)
{
    const char* subsystem_names[] = {
        "Memory Management", "Interrupt Handling", "Timing", "Scheduler",
        "Process Management", "IPC", "System Calls", "Networking", 
        "SMP Support", "ACPI"
    };
    
    printk(KERN_INFO "Subsystem Status:\n");
    uint32_t status = __atomic_load_n(&subsystem_status, __ATOMIC_SEQ_CST);
    
    for (int i = 0; i < 10; i++) {
        bool available = (status & (1U << i)) != 0;
        const char* status_str = available ? "OK" : 
                                (i == SUBSYS_NETWORK_BIT || i == SUBSYS_SMP_BIT || i == SUBSYS_ACPI_BIT ? 
                                 "NOT AVAILABLE" : "FAILED");
        printk(KERN_INFO "  %s: %s\n", subsystem_names[i], status_str);
    }
    
    printk(KERN_INFO "CPUs: %u detected, %u online\n", 
           __atomic_load_n(&cpu_count, __ATOMIC_SEQ_CST),
           __atomic_load_n(&cpus_online, __ATOMIC_SEQ_CST));
    
    // Print error summary if any occurred
    uint32_t errors = __atomic_load_n(&error_count, __ATOMIC_SEQ_CST);
    if (errors > 0) {
        printk(KERN_INFO "Initialization errors: %u\n", errors);
        for (uint32_t i = 0; i < errors && i < 16; i++) {
            printk(KERN_INFO "  %s: code=%d, %s\n", 
                   phase_errors[i].subsystem_name,
                   phase_errors[i].error_code,
                   phase_errors[i].error_message);
        }
    }
}

// Record phase error for debugging
static void record_phase_error(const char *subsystem, int error_code, const char *message)
{
    uint32_t idx = __atomic_fetch_add(&error_count, 1, __ATOMIC_SEQ_CST);
    if (idx < 16) {
        phase_errors[idx].subsystem_name = subsystem;
        phase_errors[idx].error_code = error_code;
        phase_errors[idx].error_message = message;
        phase_errors[idx].timestamp = get_system_time();
    }
}

// Emergency panic that works with minimal subsystems
static void emergency_panic(const char *fmt, ...)
{
    va_list args;
    char buffer[256];
    
    // Try serial output first as it's most reliable
    init_emergency_serial();
    
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    
    // Output to all available channels
    emergency_serial_print("[PANIC] ");
    emergency_serial_print(buffer);
    emergency_serial_print("\n");
    
    // Try normal panic if console might work
    if (g_boot_info && g_boot_info->framebuffer_base != 0) {
        panic("%s", buffer);
    }
    
    // Halt all CPUs
    disable_interrupts();
    while (1) {
        asm volatile("cli; hlt" ::: "memory");
    }
}

// Log memory map for debugging framebuffer/initrd overlaps
static void log_memory_map(BootInfo *boot_info)
{
    DEBUG_PRINT("Memory map dump:\n");
    DEBUG_PRINT("  Map size: %lu bytes, descriptor size: %u\n",
                boot_info->memory_map_size, boot_info->descriptor_size);
    DEBUG_PRINT("  Framebuffer: 0x%lx-0x%lx (%lu bytes)\n",
                boot_info->framebuffer_base,
                boot_info->framebuffer_base + boot_info->framebuffer_size,
                boot_info->framebuffer_size);
    if (boot_info->initrd_base != 0) {
        DEBUG_PRINT("  InitRD: 0x%lx-0x%lx (%lu bytes)\n",
                    boot_info->initrd_base,
                    boot_info->initrd_base + boot_info->initrd_size,
                    boot_info->initrd_size);
    }
}

// Validate boot information structure 
static void validate_boot_info(BootInfo *boot_info)
{
    if (!boot_info) {
        emergency_panic("Boot info is NULL");
    }
    
    // Validate memory map
    if (!boot_info->memory_map || boot_info->memory_map_size == 0) {
        emergency_panic("Invalid memory map in boot info");
    }
    
    // Validate memory map descriptors for corruption-causing issues
    if (boot_info->descriptor_size < 20) {  // Minimum UEFI descriptor size
        emergency_panic("Memory map descriptor size too small: %lu", boot_info->descriptor_size);
    }
    
    // Check for reasonable memory map size based on system constraints
    // Large memory systems can have extensive maps, so allow up to 16MB
    if (boot_info->memory_map_size > (16 * 1024 * 1024)) {
        emergency_panic("Memory map size excessively large: %lu bytes", boot_info->memory_map_size);
    }
    
    // Validate framebuffer 
    validate_framebuffer(boot_info);
    
    // Validate memory regions for overlaps
    validate_memory_regions(boot_info);
    
    // Safe command line handling - handle exactly 255 characters properly
    size_t cmdline_len = 0;
    for (size_t i = 0; i < 255; i++) {
        if (boot_info->cmdline[i] == '\0') {
            cmdline_len = i;
            break;
        }
    }
    
    if (cmdline_len == 0 && boot_info->cmdline[254] != '\0') {
        // String fills entire 255 bytes without null terminator
        boot_info->cmdline[254] = '\0';
        cmdline_len = 254;
        printk(KERN_WARN "Command line truncated to 254 characters\n");
    }
    
    // Zero out remaining buffer for security
    if (cmdline_len < 255) {
        memset(&boot_info->cmdline[cmdline_len + 1], 0, 255 - cmdline_len - 1);
    }
    // Ensure last byte is always zero
    boot_info->cmdline[255] = '\0';
    
    DEBUG_PRINT("Boot info validation passed\n");
}

// Validate framebuffer configuration
static void validate_framebuffer(BootInfo *boot_info)
{
    if (boot_info->framebuffer_base != 0) {
        if (boot_info->framebuffer_width == 0 || 
            boot_info->framebuffer_height == 0 ||
            boot_info->framebuffer_pitch == 0) {
            log_memory_map(boot_info);
            emergency_panic("Invalid framebuffer parameters");
        }
        
        // Check for page alignment (important for DMA and mmap)
        if (!IS_PAGE_ALIGNED(boot_info->framebuffer_base)) {
            log_memory_map(boot_info);
            emergency_panic("Framebuffer base not page-aligned: 0x%lx - DMA operations will fail", 
                   boot_info->framebuffer_base);
        }
        
        // Sanity check: pitch should be at least width * bytes_per_pixel (assuming 32bpp)
        uint32_t min_pitch = boot_info->framebuffer_width * 4;
        if (boot_info->framebuffer_pitch < min_pitch) {
            log_memory_map(boot_info);
            emergency_panic("Invalid framebuffer pitch: %u < %u (minimum for 32bpp) - will corrupt memory",
                   boot_info->framebuffer_pitch, min_pitch);
        }
        
        // Check for extreme pitch values that could cause issues
        if (boot_info->framebuffer_pitch > boot_info->framebuffer_width * 32) {
            log_memory_map(boot_info);
            emergency_panic("Framebuffer pitch unreasonably large: %u - exceeds hardware limits", 
                   boot_info->framebuffer_pitch);
        }
    }
}

// Validate memory regions for overlaps and reserved areas
static void validate_memory_regions(BootInfo *boot_info)
{
    // Check framebuffer overlap with initrd
    if (boot_info->framebuffer_base != 0 && boot_info->initrd_base != 0) {
        uint64_t fb_end = boot_info->framebuffer_base + boot_info->framebuffer_size;
        uint64_t initrd_end = boot_info->initrd_base + boot_info->initrd_size;
        
        // Check for wraparound
        if (fb_end < boot_info->framebuffer_base) {
            log_memory_map(boot_info);
            emergency_panic("Framebuffer address wraparound detected - memory layout corrupted");
        }
        if (initrd_end < boot_info->initrd_base) {
            log_memory_map(boot_info);
            emergency_panic("InitRD address wraparound detected - memory layout corrupted");
        }
        
        // Check for overlap
        if ((boot_info->framebuffer_base < initrd_end) && 
            (fb_end > boot_info->initrd_base)) {
            log_memory_map(boot_info);
            emergency_panic("Framebuffer overlaps with initrd - memory corruption will occur");
        }
    }
    
    // Validate kernel image location to prevent memory corruption
    extern char kernel_start, kernel_end;
    uint64_t kernel_size = (uint64_t)&kernel_end - (uint64_t)&kernel_start;
    
    // Check if kernel overlaps with framebuffer
    if (boot_info->framebuffer_base != 0) {
        uint64_t fb_end = boot_info->framebuffer_base + boot_info->framebuffer_size;
        if (((uint64_t)&kernel_start < fb_end) && 
            ((uint64_t)&kernel_end > boot_info->framebuffer_base)) {
            log_memory_map(boot_info);
            emergency_panic("Kernel image overlaps with framebuffer - bootloader error");
        }
    }
    
    // Check if kernel overlaps with initrd
    if (boot_info->initrd_base != 0) {
        uint64_t initrd_end = boot_info->initrd_base + boot_info->initrd_size;
        if (((uint64_t)&kernel_start < initrd_end) && 
            ((uint64_t)&kernel_end > boot_info->initrd_base)) {
            log_memory_map(boot_info);
            emergency_panic("Kernel image overlaps with initrd - bootloader error");
        }
    }
}

// Initialize early console output
static void init_early_console(BootInfo *boot_info)
{
    console_init(boot_info->framebuffer_base,
                 boot_info->framebuffer_width,
                 boot_info->framebuffer_height,
                 boot_info->framebuffer_pitch);
    
    // Also initialize printk logging - check if console initialization succeeded
    if (printk_init() != 0) {
        // Cannot log errors if printk fails - try basic serial output
        init_emergency_output();
    }
}

// Initialize memory management subsystem
static int init_memory_management(BootInfo *boot_info)
{
    int result;
    
    // Initialize physical page allocator using UEFI memory map 
    result = page_alloc_init(boot_info->memory_map,
                            boot_info->memory_map_size,
                            boot_info->descriptor_size);
    if (result != 0) {
        return result;
    }
    
    // Set up virtual memory management - pass physical addresses
    result = vmem_init(boot_pml4, boot_pdpt, boot_pd);
    if (result != 0) {
        return result;
    }
    
    // Initialize kernel heap allocator
    result = kmalloc_init();
    if (result != 0) {
        return result;
    }
    
    // Set up proper page tables (replace boot page tables) 
    result = paging_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

// Initialize interrupt and exception handling
static int init_interrupt_handling(void)
{
    int result;
    
    // Set up proper IDT with all handlers
    result = irq_init();
    if (result != 0) {
        return result;
    }
    
    // Initialize PIC/APIC
    result = pic_init();
    if (result != 0) {
        return result;
    }
    
    // Set up ISRs for common exceptions
    result = isr_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

// Initialize task scheduling
static int init_scheduling(void)
{
    int result;
    
    // Initialize scheduler data structures
    result = scheduler_init();
    if (result != 0) {
        return result;
    }
    
    // Set up thread management 
    result = thread_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

// Initialize process management
static int init_process_management(void)
{
    int result;
    
    // Initialize process table and management 
    result = process_init();
    if (result != 0) {
        return result;
    }
    
    // Initialize exec() and program loading 
    result = exec_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

// Initialize IPC subsystem
static int init_ipc_subsystem(void)
{
    int result;
    
    // Initialize core IPC
    result = ipc_init();
    if (result != 0) {
        return result;
    }
    
    // Initialize message queues
    result = msgqueue_init();
    if (result != 0) {
        return result;
    }
    
    // Initialize pipes
    result = pipe_init();
    if (result != 0) {
        return result;
    }
    
    // Initialize shared memory
    result = shm_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

// Initialize system call interface
static int init_system_calls(void)
{
    int result;
    
    // Set up syscall dispatcher
    result = syscall_init();
    if (result != 0) {
        return result;
    }
    
    // Register all system calls
    result = syscall_table_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

// Initialize timing subsystem
static int init_timing(void)
{
    int result;
    
    // Initialize system timer
    result = timer_init();
    if (result != 0) {
        return result;
    }
    
    // Initialize RTC
    result = rtc_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

// Initialize networking stack
static int init_networking(void)
{
    int result;
    
    // Initialize core networking
    result = net_init();
    if (result != 0) {
        return result;
    }
    
    // Initialize socket layer
    result = socket_init();
    if (result != 0) {
        // Provide stub socket layer for compatibility
        socket_init_stub();
        return result;
    }
    
    // Initialize IP layer
    result = ip_init();
    if (result != 0) {
        return result;
    }
    
    // Initialize TCP
    result = tcp_init();
    if (result != 0) {
        return result;
    }
    
    // Initialize UDP 
    result = udp_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

// Initialize security subsystem
static int init_security(void)
{
    int result;
    
    // Initialize core security hooks
    result = security_init();
    if (result != 0) {
        return result;
    }
    
    // Initialize integrity checking
    result = integrity_init();
    if (result != 0) {
        return result;
    }
    
    // Initialize sandboxing
    result = sandbox_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

// Validate that all critical subsystem functions exist at compile time
static void validate_critical_functions(void)
{
    // This function forces compile-time errors if critical functions are missing
    // The compiler will optimize this away in release builds
    volatile void *funcs[] = {
        (void*)console_init,
        (void*)printk_init, 
        (void*)scheduler_init,
        (void*)process_init,
        (void*)scheduler_start,
        (void*)process_create_user,
        (void*)page_alloc_init,
        (void*)vmem_init,
        (void*)irq_init,
        (void*)syscall_init,
        (void*)timer_init,
        (void*)get_system_time,
        NULL
    };
    (void)funcs; // Suppress unused variable warning
}

// Launch the first userspace process (/user/init)
static void launch_init_process(void)
{
    int result;
    pid_t init_pid;
    
    printk(KERN_INFO "Launching init process...\n");
    
    // Create the init process with validated command line
    init_pid = process_create_user("/user/init", g_boot_info->cmdline);
    if (init_pid < 0) {
        emergency_panic("Failed to create init process: %d", init_pid);
    }
    
    printk(KERN_OK "Init process created with PID %d\n", init_pid);
    
    // Create and start the kernel idle task - this is critical
    result = thread_create_kernel(kernel_idle_task, NULL, "idle");
    if (result < 0) {
        emergency_panic("Failed to create idle task: %d", result);
    }
    
    // Start the scheduler - this will switch to init process
    scheduler_start();
    
    // We should never reach here
    emergency_panic("scheduler_start() returned");
}

// Kernel idle task, runs when no other tasks are ready
static void kernel_idle_task(void)
{
    // Single startup message to avoid log flooding
    printk(KERN_INFO "Kernel idle task started\n");
    
    while (1) {
        // Memory barrier to ensure visibility of scheduler updates
        memory_barrier();
        
        // Check for runnable tasks with interrupts disabled to avoid race
        bool interrupts_enabled = are_interrupts_enabled();
        if (interrupts_enabled) {
            disable_interrupts();
        }
        
        bool has_tasks = scheduler_has_runnable_tasks();
        
        if (has_tasks) {
            // Re-enable interrupts and yield to scheduler
            if (interrupts_enabled) {
                enable_interrupts();
            }
            scheduler_yield();
        } else {
            // No tasks available - enable interrupts before halting
            // This prevents race where task becomes available after check
            if (interrupts_enabled) {
                enable_interrupts();
                // Small delay to allow interrupt processing
                cpu_pause();
            }
            
            // Use monitor/mwait if available for power efficiency
            if (cpu_has_monitor_mwait()) {
                asm volatile("monitor" ::: "memory");
                asm volatile("mwait" ::: "memory");
            } else {
                // Fall back to traditional hlt with interrupts enabled
                asm volatile("hlt" ::: "memory");
            }
        }
    }
}

// Kernel information functions
bool is_kernel_initialized(void)
{
    return __atomic_load_n(&kernel_initialized, __ATOMIC_SEQ_CST);
}

uint64_t get_kernel_uptime(void)
{
    if (!__atomic_load_n(&kernel_initialized, __ATOMIC_SEQ_CST)) {
        return 0;
    }
    return NS_TO_MS(get_system_time() - kernel_boot_start_time);
}

BootInfo *get_boot_info(void)
{
    return g_boot_info;
}

// Get subsystem status for other kernel modules (SMP-safe)
bool is_subsystem_available(int subsystem_bit)
{
    if (subsystem_bit < 0 || subsystem_bit >= 32) {
        return false;
    }
    return SUBSYS_IS_SET(subsystem_bit);
}

// SMP support functions
static int init_smp(void)
{
    int result;
    
    // Initialize ACPI for processor detection
    result = acpi_init();
    if (result != 0) {
        printk(KERN_WARN "ACPI initialization failed: %d\n", result);
        return result;
    }
    SUBSYS_SET(SUBSYS_ACPI_BIT);
    
    // Detect available processors
    cpu_count = acpi_get_processor_count();
    printk(KERN_INFO "ACPI reports %u processors available\n", cpu_count);
    
    if (cpu_count > CONFIG_MAX_CPUS) {
        printk(KERN_WARN "Found %u CPUs, limiting to %u\n", cpu_count, CONFIG_MAX_CPUS);
        cpu_count = CONFIG_MAX_CPUS;
    }
    
    // Initialize per-CPU data structures with validation
    result = percpu_init(cpu_count);
    if (result != 0) {
        return result;
    }
    
    // Validate per-CPU data structures before proceeding
    result = percpu_validate_all();
    if (result != 0) {
        emergency_panic("Per-CPU data validation failed: %d", result);
    }
    
    // Initialize SMP-aware scheduler with barriers
    result = scheduler_init_smp(cpu_count);
    if (result != 0) {
        return result;
    }
    
    // Ensure all initialization is visible before marking ready
    memory_barrier();
    
    // Mark bootstrap processor as online
    __atomic_store_n(&cpus_online, 1, __ATOMIC_SEQ_CST);
    
    return 0;
}

static void start_application_processors(void)
{
    uint32_t successful_boots = 0;
    
    for (uint32_t cpu_id = 1; cpu_id < cpu_count; cpu_id++) {
        printk(KERN_INFO "Booting CPU %u...\n", cpu_id);
        
        bool cpu_started = false;
        
        // Try booting with retries
        for (int retry = 0; retry <= CONFIG_AP_BOOT_RETRIES && !cpu_started; retry++) {
            if (retry > 0) {
                printk(KERN_INFO "Retrying CPU %u boot (attempt %d)...\n", cpu_id, retry + 1);
            }
            
            int result = smp_boot_cpu(cpu_id);
            if (result != 0) {
                printk(KERN_WARN "Failed to start CPU %u: %d\n", cpu_id, result);
                continue;
            }
            
            // Wait for AP to come online with timeout
            uint64_t start_time = get_system_time();
            uint64_t timeout_ns = CONFIG_AP_BOOT_TIMEOUT_MS * 1000000UL;
            
            while ((get_system_time() - start_time) < timeout_ns) {
                if (is_cpu_online(cpu_id)) {
                    cpu_started = true;
                    break;
                }
                cpu_relax();  // Yield CPU briefly
            }
            
            if (cpu_started) {
                __atomic_add_fetch(&cpus_online, 1, __ATOMIC_SEQ_CST);
                successful_boots++;
                printk(KERN_OK "CPU %u online\n", cpu_id);
            } else {
                printk(KERN_WARN "CPU %u boot timeout (attempt %d)\n", cpu_id, retry + 1);
            }
        }
        
        if (!cpu_started) {
            printk(KERN_WARN "CPU %u failed to start after %d attempts\n", cpu_id, CONFIG_AP_BOOT_RETRIES + 1);
            mark_cpu_offline(cpu_id);
        }
    }
    
    uint32_t total_online = __atomic_load_n(&cpus_online, __ATOMIC_SEQ_CST);
    printk(KERN_INFO "SMP initialization complete: %u/%u CPUs online\n",
           total_online, cpu_count);
    
    // Validate scheduler state after AP startup
    if (validate_scheduler_smp_state() != 0) {
        emergency_panic("Scheduler SMP state corrupted after AP startup");
    }
    
    // Update scheduler with actual online CPU count
    scheduler_update_cpu_count(total_online);
}

// Remove the now-redundant forward declarations section
// Kernel image symbols from linker
extern char kernel_start;
extern char kernel_end;

#ifndef CONFIG_MAX_CPUS
#define CONFIG_MAX_CPUS 64
#endif

#ifndef HAVE_SECURITY_STUB
// Define this if security_init_stub() function exists in your kernel
// #define HAVE_SECURITY_STUB
#endif

// Weak symbol for security stub - allows linking without defining the function
void __attribute__((weak)) security_init_stub(void) {
    // Default stub implementation does nothing
}
