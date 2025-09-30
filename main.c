// init/main.c
// NOTE: This is more of a draft than a final version

// Core types must come first to establish base definitions
#include <types.h>
#include <stdarg.h>
#include <string.h>

// Kernel subsystem headers in dependency order
#include <init.h>
#include <mm.h>
#include <irq.h>
#include <time.h>
#include <sched.h>
#include <proc.h>
#include <ipc.h>
#include <syscall.h>
#include <console.h>
#include <printk.h>
#include <net.h>
#include <security.h>

// Kernel log levels
#define KERN_PANIC  "[PANIC] "
#define KERN_ERROR  "[ERROR] "
#define KERN_WARN   "[WARN]  "
#define KERN_INFO   "[INFO]  "
#define KERN_OK     "[OK]    "
#define KERN_DEBUG  "[DEBUG] "
#define KERN_NONE   ""

// External symbols from bootloader and linker script
extern uint64_t *boot_pml4;         // Pointer to boot page table
extern uint64_t *boot_pdpt;         // Pointer to PDPT
extern uint64_t *boot_pd;           // Pointer to PD
extern char kernel_start;           // Start of kernel image
extern char kernel_end;             // End of kernel image

// Boot information from UEFI bootloader
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
    
    uint64_t rsdp_address;
    uint64_t initrd_base;
    uint64_t initrd_size;
    
    char     cmdline[256];
} __attribute__((packed)) BootInfo;

// Debug macro that compiles out in release builds
#if defined(CONFIG_DEBUG) && !defined(NDEBUG)
#define DEBUG_PRINT(fmt, ...) printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) do { } while (0)
#endif

// Time conversion with rounding
#define NS_TO_MS(ns) (((ns) + 500000UL) / 1000000UL)
#define NS_TO_US(ns) (((ns) + 500UL) / 1000UL)

// Version information
#define CINNAMON_VERSION_MAJOR  0
#define CINNAMON_VERSION_MINOR  1
#define CINNAMON_VERSION_PATCH  0
#define CINNAMON_BUILD_DATE     __DATE__
#define CINNAMON_BUILD_TIME     __TIME__

// Memory alignment check
#define IS_PAGE_ALIGNED(addr) (((addr) & 0xFFF) == 0)

// SMP configuration
#ifndef CONFIG_MAX_CPUS
#define CONFIG_MAX_CPUS 64
#endif

#ifndef CONFIG_AP_BOOT_TIMEOUT_MS
#define CONFIG_AP_BOOT_TIMEOUT_MS 3000
#endif

#ifndef CONFIG_AP_BOOT_RETRIES
#define CONFIG_AP_BOOT_RETRIES 1
#endif

// Global kernel state
static BootInfo *g_boot_info = NULL;
static volatile uint32_t kernel_initialized = 0;  // Atomic flag, not bool
static uint64_t kernel_boot_start_time = 0;
static uint64_t kernel_ready_time = 0;
static uint64_t phase_times[5] = {0};
static volatile uint32_t subsystem_status = 0;
static volatile uint32_t cpu_count = 1;
static volatile uint32_t cpus_online = 0;

// Per-phase error tracking
typedef struct {
    int error_code;
    const char *subsystem_name;
    const char *error_message;
    uint64_t timestamp;
} __attribute__((aligned(64))) phase_error_t;  // Cache line alignment for SMP

static phase_error_t phase_errors[16] = {0};
static volatile uint32_t error_count = 0;

// Subsystem status bits for atomic access
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

// Function declarations for external subsystems
int console_init(uint64_t fb_base, uint32_t width, uint32_t height, uint32_t pitch);
void console_clear(void);
int printk_init(void);
int printk(const char *fmt, ...);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);

int page_alloc_init(void *memory_map, uint64_t map_size, uint64_t descriptor_size);
int vmem_init(uint64_t pml4, uint64_t pdpt, uint64_t pd);
int kmalloc_init(void);
int paging_init(void);

int irq_init(void);
int pic_init(void);
int isr_init(void);

int scheduler_init(void);
int thread_init(void);
int process_init(void);
int exec_init(void);
void scheduler_start(void) __attribute__((noreturn));
bool scheduler_has_runnable_tasks(void);
void scheduler_yield(void);
int thread_create_kernel(void (*func)(void), void *arg, const char *name);
pid_t process_create_user(const char *path, const char *cmdline);

int ipc_init(void);
int msgqueue_init(void);
int pipe_init(void);
int shm_init(void);

int syscall_init(void);
int syscall_table_init(void);

int timer_init(void);
int rtc_init(void);
uint64_t get_system_time(void);

int net_init(void);
int socket_init(void);
void socket_init_stub(void);
int ip_init(void);
int tcp_init(void);
int udp_init(void);

int security_init(void);
int integrity_init(void);
int sandbox_init(void);

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

size_t strnlen(const char *s, size_t maxlen);
void *memset(void *s, int c, size_t n);

void panic(const char *fmt, ...) __attribute__((noreturn));
void __attribute__((weak)) security_init_stub(void) {}

// Internal function declarations
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
static void validate_critical_functions(void);

// Main kernel entry point from assembly
void kernel_main(BootInfo *boot_info)
{
    int result;
    
    validate_critical_functions();
    
    kernel_boot_start_time = get_system_time();
    if (kernel_boot_start_time == 0) {
        kernel_boot_start_time = 1;
    }
    
    g_boot_info = boot_info;
    validate_boot_info(boot_info);
    
    if (boot_info->framebuffer_base != 0) {
        init_early_console(boot_info);
    } else {
        init_serial_console();
    }
    
    print_banner();
    printk(KERN_INFO "CinnamonOS kernel starting...\n");
    printk(KERN_INFO "Boot info at 0x%lx\n", (uint64_t)boot_info);

    // Phase 1: Core subsystems
    printk(KERN_INFO "Phase 1: Initializing core subsystems...\n");
    uint64_t phase1_start = get_system_time();
    
    result = init_memory_management(boot_info);
    if (result != 0) {
        record_phase_error("Memory Management", result, "Memory subsystem initialization failure");
        emergency_panic("Memory management initialization returned error %d", result);
    }
    SUBSYS_SET(SUBSYS_MEMORY_BIT);
    printk(KERN_OK "Memory management initialized\n");
    
    result = init_interrupt_handling();
    if (result != 0) {
        record_phase_error("Interrupt Handling", result, "Interrupt subsystem initialization failure");
        emergency_panic("Interrupt handling initialization returned error %d", result);
    }
    SUBSYS_SET(SUBSYS_INTERRUPTS_BIT);
    printk(KERN_OK "Interrupt handling initialized\n");
    
    result = init_timing();
    if (result != 0) {
        record_phase_error("Timing", result, "Timing subsystem initialization failure");
        emergency_panic("Timing initialization returned error %d", result);
    }
    SUBSYS_SET(SUBSYS_TIMING_BIT);
    printk(KERN_OK "Timing subsystem initialized\n");
    
    result = init_smp();
    if (result != 0) {
        record_phase_error("SMP", result, "SMP initialization returned error");
        printk(KERN_WARN "SMP initialization returned error %d (continuing single-core)\n", result);
    } else {
        SUBSYS_SET(SUBSYS_SMP_BIT);
        printk(KERN_OK "SMP support initialized (%u CPUs detected)\n", cpu_count);
    }
    
    phase_times[0] = get_system_time() - phase1_start;
    printk(KERN_INFO "Phase 1 complete in %lu ms\n", NS_TO_MS(phase_times[0]));

    // Phase 2: Process and scheduling
    printk(KERN_INFO "Phase 2: Initializing process management...\n");
    uint64_t phase2_start = get_system_time();
    
    result = init_scheduling();
    if (result != 0) {
        record_phase_error("Scheduler", result, "Scheduler initialization failure");
        emergency_panic("Scheduler initialization returned error %d", result);
    }
    SUBSYS_SET(SUBSYS_SCHEDULER_BIT);
    printk(KERN_OK "Scheduler initialized\n");
    
    result = init_process_management();
    if (result != 0) {
        record_phase_error("Process Management", result, "Process subsystem initialization failure");
        emergency_panic("Process management initialization returned error %d", result);
    }
    SUBSYS_SET(SUBSYS_PROCESS_BIT);
    printk(KERN_OK "Process management initialized\n");
    
    result = init_ipc_subsystem();
    if (result != 0) {
        record_phase_error("IPC", result, "IPC subsystem initialization failure");
        emergency_panic("IPC initialization returned error %d", result);
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
        record_phase_error("System Calls", result, "System call interface initialization failure");
        emergency_panic("System call initialization returned error %d", result);
    }
    SUBSYS_SET(SUBSYS_SYSCALLS_BIT);
    printk(KERN_OK "System calls initialized\n");
    
    phase_times[2] = get_system_time() - phase3_start;
    printk(KERN_INFO "Phase 3 complete in %lu ms\n", NS_TO_MS(phase_times[2]));
    
    // Phase 4: Optional subsystems
    printk(KERN_INFO "Phase 4: Initializing optional subsystems...\n");
    uint64_t phase4_start = get_system_time();
    
    result = init_networking();
    if (result != 0) {
        record_phase_error("Networking", result, "Network initialization returned error");
        printk(KERN_WARN "Networking initialization returned error %d (network features disabled)\n", result);
        disable_network_features();
    } else {
        SUBSYS_SET(SUBSYS_NETWORK_BIT);
        printk(KERN_OK "Network stack initialized\n");
    }
    
    result = init_security();
    if (result != 0) {
        record_phase_error("Security", result, "Security initialization returned error");
#ifdef CONFIG_DEBUG
        printk(KERN_WARN "Security initialization returned error %d - using stub security\n", result);
        security_init_stub();
#else
        emergency_panic("Security initialization returned error %d - system security compromised", result);
#endif
    } else {
        printk(KERN_OK "Security subsystem initialized\n");
    }
    
    phase_times[3] = get_system_time() - phase4_start;
    printk(KERN_INFO "Phase 4 complete in %lu ms\n", NS_TO_MS(phase_times[3]));
    
    // Phase 5: Finalize and launch userspace
    printk(KERN_INFO "Phase 5: Finalizing kernel startup...\n");
    uint64_t phase5_start = get_system_time();
    
    kernel_ready_time = get_system_time();
    __atomic_store_n(&kernel_initialized, true, __ATOMIC_SEQ_CST);
    
    uint64_t total_init_time = kernel_ready_time - kernel_boot_start_time;
    printk(KERN_OK "Kernel initialization complete in %lu ms\n", NS_TO_MS(total_init_time));
    
    printk(KERN_INFO "Phase timing - 1: %lu ms, 2: %lu ms, 3: %lu ms, 4: %lu ms\n",
           NS_TO_MS(phase_times[0]), NS_TO_MS(phase_times[1]),
           NS_TO_MS(phase_times[2]), NS_TO_MS(phase_times[3]));
    
    print_subsystem_status();
    
    if (SUBSYS_IS_SET(SUBSYS_SMP_BIT) && cpu_count > 1) {
        printk(KERN_INFO "Starting %u application processors...\n", cpu_count - 1);
        start_application_processors();
    }
    
    printk(KERN_INFO "Enabling interrupts...\n");
    enable_interrupts();
    
    launch_init_process();
    
    phase_times[4] = get_system_time() - phase5_start;
    printk(KERN_INFO "Phase 5 complete in %lu ms\n", NS_TO_MS(phase_times[4]));
    
    emergency_panic("kernel_main() returned - init process launch failure");
}

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

static void emergency_panic(const char *fmt, ...)
{
    static volatile uint32_t in_panic = 0;
    va_list args;
    char buffer[256];
    int written;
    
    // Prevent recursion if panic handler itself panics
    if (__atomic_exchange_n(&in_panic, 1, __ATOMIC_SEQ_CST) != 0) {
        // Already in panic, just halt
        disable_interrupts();
        while (1) {
            asm volatile("cli; hlt" ::: "memory");
        }
    }
    
    init_emergency_serial();
    
    va_start(args, fmt);
    written = vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    
    // Check for truncation
    if (written >= sizeof(buffer)) {
        buffer[sizeof(buffer) - 2] = '\n';
        buffer[sizeof(buffer) - 1] = '\0';
    }
    
    emergency_serial_print("[PANIC] ");
    emergency_serial_print(buffer);
    emergency_serial_print("\n");
    
    if (g_boot_info && g_boot_info->framebuffer_base != 0) {
        panic("%s", buffer);
    }
    
    disable_interrupts();
    while (1) {
        asm volatile("cli; hlt" ::: "memory");
    }
}

static void log_memory_map(BootInfo *boot_info)
{
    DEBUG_PRINT("Memory map details:\n");
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

static void validate_boot_info(BootInfo *boot_info)
{
    if (!boot_info) {
        emergency_panic("Boot info pointer is null");
    }
    
    if (!boot_info->memory_map || boot_info->memory_map_size == 0) {
        emergency_panic("Memory map data invalid in boot info");
    }
    
    if (boot_info->descriptor_size < 20) {
        emergency_panic("Memory map descriptor size below minimum: %lu", boot_info->descriptor_size);
    }
    
    if (boot_info->memory_map_size > (16 * 1024 * 1024)) {
        emergency_panic("Memory map size exceeds maximum: %lu bytes", boot_info->memory_map_size);
    }
    
    validate_framebuffer(boot_info);
    validate_memory_regions(boot_info);
    
    size_t cmdline_len = 0;
    for (size_t i = 0; i < 255; i++) {
        if (boot_info->cmdline[i] == '\0') {
            cmdline_len = i;
            break;
        }
    }
    
    if (cmdline_len == 0 && boot_info->cmdline[254] != '\0') {
        boot_info->cmdline[254] = '\0';
        cmdline_len = 254;
        printk(KERN_WARN "Command line truncated to 254 characters\n");
    }
    
    if (cmdline_len < 255) {
        memset(&boot_info->cmdline[cmdline_len + 1], 0, 255 - cmdline_len - 1);
    }
    boot_info->cmdline[255] = '\0';
    
    DEBUG_PRINT("Boot info validation complete\n");
}

static void validate_framebuffer(BootInfo *boot_info)
{
    if (boot_info->framebuffer_base != 0) {
        if (boot_info->framebuffer_width == 0 || 
            boot_info->framebuffer_height == 0 ||
            boot_info->framebuffer_pitch == 0) {
            log_memory_map(boot_info);
            emergency_panic("Framebuffer parameters contain zero values");
        }
        
        if (!IS_PAGE_ALIGNED(boot_info->framebuffer_base)) {
            log_memory_map(boot_info);
            emergency_panic("Framebuffer base not page-aligned: 0x%lx", 
                   boot_info->framebuffer_base);
        }
        
        uint32_t min_pitch = boot_info->framebuffer_width * 4;
        if (boot_info->framebuffer_pitch < min_pitch) {
            log_memory_map(boot_info);
            emergency_panic("Framebuffer pitch below minimum: %u < %u",
                   boot_info->framebuffer_pitch, min_pitch);
        }
        
        if (boot_info->framebuffer_pitch > boot_info->framebuffer_width * 32) {
            log_memory_map(boot_info);
            emergency_panic("Framebuffer pitch exceeds reasonable maximum: %u", 
                   boot_info->framebuffer_pitch);
        }
    }
}

static void validate_memory_regions(BootInfo *boot_info)
{
    if (boot_info->framebuffer_base != 0 && boot_info->initrd_base != 0) {
        uint64_t fb_end = boot_info->framebuffer_base + boot_info->framebuffer_size;
        uint64_t initrd_end = boot_info->initrd_base + boot_info->initrd_size;
        
        if (fb_end < boot_info->framebuffer_base) {
            log_memory_map(boot_info);
            emergency_panic("Framebuffer address wraparound detected");
        }
        if (initrd_end < boot_info->initrd_base) {
            log_memory_map(boot_info);
            emergency_panic("InitRD address wraparound detected");
        }
        
        if ((boot_info->framebuffer_base < initrd_end) && 
            (fb_end > boot_info->initrd_base)) {
            log_memory_map(boot_info);
            emergency_panic("Framebuffer region overlaps with initrd region");
        }
    }
    
    uint64_t kernel_size = (uint64_t)&kernel_end - (uint64_t)&kernel_start;
    
    if (boot_info->framebuffer_base != 0) {
        uint64_t fb_end = boot_info->framebuffer_base + boot_info->framebuffer_size;
        if (((uint64_t)&kernel_start < fb_end) && 
            ((uint64_t)&kernel_end > boot_info->framebuffer_base)) {
            log_memory_map(boot_info);
            emergency_panic("Kernel image overlaps with framebuffer region");
        }
    }
    
    if (boot_info->initrd_base != 0) {
        uint64_t initrd_end = boot_info->initrd_base + boot_info->initrd_size;
        if (((uint64_t)&kernel_start < initrd_end) && 
            ((uint64_t)&kernel_end > boot_info->initrd_base)) {
            log_memory_map(boot_info);
            emergency_panic("Kernel image overlaps with initrd region");
        }
    }
}

static void init_early_console(BootInfo *boot_info)
{
    console_init(boot_info->framebuffer_base,
                 boot_info->framebuffer_width,
                 boot_info->framebuffer_height,
                 boot_info->framebuffer_pitch);
    
    if (printk_init() != 0) {
        init_emergency_output();
    }
}

static int init_memory_management(BootInfo *boot_info)
{
    int result;
    
    result = page_alloc_init(boot_info->memory_map,
                            boot_info->memory_map_size,
                            boot_info->descriptor_size);
    if (result != 0) {
        return result;
    }
    
    result = vmem_init(boot_pml4, boot_pdpt, boot_pd);
    if (result != 0) {
        return result;
    }
    
    result = kmalloc_init();
    if (result != 0) {
        return result;
    }
    
    result = paging_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

static int init_interrupt_handling(void)
{
    int result;
    
    result = irq_init();
    if (result != 0) {
        return result;
    }
    
    result = pic_init();
    if (result != 0) {
        return result;
    }
    
    result = isr_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

static int init_scheduling(void)
{
    int result;
    
    result = scheduler_init();
    if (result != 0) {
        return result;
    }
    
    result = thread_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

static int init_process_management(void)
{
    int result;
    
    result = process_init();
    if (result != 0) {
        return result;
    }
    
    result = exec_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

static int init_ipc_subsystem(void)
{
    int result;
    
    result = ipc_init();
    if (result != 0) {
        return result;
    }
    
    result = msgqueue_init();
    if (result != 0) {
        return result;
    }
    
    result = pipe_init();
    if (result != 0) {
        return result;
    }
    
    result = shm_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

static int init_system_calls(void)
{
    int result;
    
    result = syscall_init();
    if (result != 0) {
        return result;
    }
    
    result = syscall_table_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

static int init_timing(void)
{
    int result;
    
    result = timer_init();
    if (result != 0) {
        return result;
    }
    
    result = rtc_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

static int init_networking(void)
{
    int result;
    
    result = net_init();
    if (result != 0) {
        return result;
    }
    
    result = socket_init();
    if (result != 0) {
        socket_init_stub();
        return result;
    }
    
    result = ip_init();
    if (result != 0) {
        return result;
    }
    
    result = tcp_init();
    if (result != 0) {
        return result;
    }
    
    result = udp_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

static int init_security(void)
{
    int result;
    
    result = security_init();
    if (result != 0) {
        return result;
    }
    
    result = integrity_init();
    if (result != 0) {
        return result;
    }
    
    result = sandbox_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

static void validate_critical_functions(void)
{
    // Compile-time validation of critical function existence
    // Optimized away in release builds
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
    (void)funcs;
}

static void launch_init_process(void)
{
    int result;
    pid_t init_pid;
    
    printk(KERN_INFO "Launching init process...\n");
    
    init_pid = process_create_user("/user/init", g_boot_info->cmdline);
    if (init_pid < 0) {
        emergency_panic("Init process creation returned error %d", init_pid);
    }
    
    printk(KERN_OK "Init process created with PID %d\n", init_pid);
    
    result = thread_create_kernel(kernel_idle_task, NULL, "idle");
    if (result < 0) {
        emergency_panic("Idle task creation returned error %d", result);
    }
    
    scheduler_start();
    
    emergency_panic("scheduler_start() returned to caller");
}

static void kernel_idle_task(void)
{
    printk(KERN_INFO "Kernel idle task started\n");
    
    while (1) {
        memory_barrier();
        
        bool interrupts_enabled = are_interrupts_enabled();
        if (interrupts_enabled) {
            disable_interrupts();
        }
        
        bool has_tasks = scheduler_has_runnable_tasks();
        
        if (has_tasks) {
            if (interrupts_enabled) {
                enable_interrupts();
            }
            scheduler_yield();
        } else {
            if (interrupts_enabled) {
                enable_interrupts();
                cpu_pause();
            }
            
            if (cpu_has_monitor_mwait()) {
                asm volatile("monitor" ::: "memory");
                asm volatile("mwait" ::: "memory");
            } else {
                asm volatile("hlt" ::: "memory");
            }
        }
    }
}

// Kernel status query functions
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

bool is_subsystem_available(int subsystem_bit)
{
    if (subsystem_bit < 0 || subsystem_bit >= 32) {
        return false;
    }
    return SUBSYS_IS_SET(subsystem_bit);
}

// SMP initialization and AP startup
static int init_smp(void)
{
    int result;
    
    result = acpi_init();
    if (result != 0) {
        printk(KERN_WARN "ACPI initialization returned error %d\n", result);
        return result;
    }
    SUBSYS_SET(SUBSYS_ACPI_BIT);
    
    cpu_count = acpi_get_processor_count();
    printk(KERN_INFO "ACPI reports %u processors available\n", cpu_count);
    
    if (cpu_count > CONFIG_MAX_CPUS) {
        printk(KERN_WARN "Found %u CPUs, limiting to %u\n", cpu_count, CONFIG_MAX_CPUS);
        cpu_count = CONFIG_MAX_CPUS;
    }
    
    result = percpu_init(cpu_count);
    if (result != 0) {
        return result;
    }
    
    result = percpu_validate_all();
    if (result != 0) {
        emergency_panic("Per-CPU data validation returned error %d", result);
    }
    
    result = scheduler_init_smp(cpu_count);
    if (result != 0) {
        return result;
    }
    
    memory_barrier();
    
    __atomic_store_n(&cpus_online, 1, __ATOMIC_SEQ_CST);
    
    return 0;
}

static void start_application_processors(void)
{
    uint32_t successful_boots = 0;
    
    for (uint32_t cpu_id = 1; cpu_id < cpu_count; cpu_id++) {
        printk(KERN_INFO "Booting CPU %u...\n", cpu_id);
        
        bool cpu_started = false;
        
        for (int retry = 0; retry <= CONFIG_AP_BOOT_RETRIES && !cpu_started; retry++) {
            if (retry > 0) {
                printk(KERN_INFO "Retrying CPU %u boot (attempt %d)...\n", cpu_id, retry + 1);
            }
            
            int result = smp_boot_cpu(cpu_id);
            if (result != 0) {
                printk(KERN_WARN "CPU %u boot returned error %d\n", cpu_id, result);
                continue;
            }
            
            uint64_t start_time = get_system_time();
            uint64_t timeout_ns = CONFIG_AP_BOOT_TIMEOUT_MS * 1000000UL;
            
            while ((get_system_time() - start_time) < timeout_ns) {
                if (is_cpu_online(cpu_id)) {
                    cpu_started = true;
                    break;
                }
                cpu_relax();
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
            printk(KERN_WARN "CPU %u did not start after %d attempts\n", cpu_id, CONFIG_AP_BOOT_RETRIES + 1);
            mark_cpu_offline(cpu_id);
        }
    }
    
    uint32_t total_online = __atomic_load_n(&cpus_online, __ATOMIC_SEQ_CST);
    printk(KERN_INFO "SMP initialization complete: %u/%u CPUs online\n",
           total_online, cpu_count);
    
    if (validate_scheduler_smp_state() != 0) {
        emergency_panic("Scheduler SMP state validation failure after AP startup");
    }
    
    scheduler_update_cpu_count(total_online);
}

// AP entry point for secondary processors
void __attribute__((section(".init"))) kernel_main_ap(uint32_t cpu_id)
{
    // Initialize per-CPU structures for this AP
    // Note: Core memory management and IDT already set up by BSP
    
    printk(KERN_INFO "AP %u: Initializing...\n", cpu_id);
    
    // Load per-CPU GDT and IDT
    // Each AP needs its own interrupt stack
    
    // Initialize local APIC for this CPU
    // This is typically done in pic_init() for BSP
    
    // Mark this CPU as online
    __atomic_add_fetch(&cpus_online, 1, __ATOMIC_SEQ_CST);
    
    printk(KERN_INFO "AP %u: Online\n", cpu_id);
    
    // Enable interrupts and enter scheduler
    enable_interrupts();
    
    // Enter idle loop - scheduler will assign tasks
    kernel_idle_task();
    
    // Should never reach here
    emergency_panic("AP %u: Idle loop returned", cpu_id);
}
