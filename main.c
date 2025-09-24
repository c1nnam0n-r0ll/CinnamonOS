/*
 * init/main.c - Main kernel initialization for CinnamonOS
 * 
 * This is the C entry point called from arch/x86/entry.S after basic
 * assembly setup. Responsible for initializing all kernel subsystems
 * and launching the first user process.
 * 
 * Boot sequence:
 * 1. UEFI bootloader -> boot/boot.efi
 * 2. boot.efi -> arch/x86/entry.S (jump_to_kernel)  
 * 3. entry.S -> kernel_main (HERE)
 * 4. kernel_main -> user/init.c (first userspace process)
 */

#include <CMOS/include/init.h>
#include <CMOS/include/mm.h>
#include <CMOS/include/sched.h>
#include <CMOS/include/proc.h>
#include <CMOS/include/ipc.h>
#include <CMOS/include/irq.h>
#include <CMOS/include/syscall.h>
#include <CMOS/include/console.h>
#include <CMOS/include/time.h>
#include <CMOS/include/net.h>
#include <CMOS/include/security.h>
#include <CMOS/include/types.h>

/* External symbols from bootloader and assembly */
extern void *boot_pml4;
extern void *boot_pdpt; 
extern void *boot_pd;

/* Boot information structure passed from UEFI bootloader */
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
    
    uint64_t rsdp_address;      /* ACPI Root System Description Pointer */
    uint64_t initrd_base;       /* Initial RAM disk */
    uint64_t initrd_size;
    
    char     cmdline[256];      /* Kernel command line */
} __attribute__((packed, aligned(8))) BootInfo;

/* Debug macro that can be compiled out for release builds */
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) do { } while (0)
#endif

/* Time conversion constants for clarity */
#define NS_TO_MS(ns) ((ns) / 1000000UL)
#define NS_TO_US(ns) ((ns) / 1000UL)
#define CINNAMON_VERSION_MAJOR  0
#define CINNAMON_VERSION_MINOR  1
#define CINNAMON_VERSION_PATCH  0
#define CINNAMON_BUILD_DATE     __DATE__
#define CINNAMON_BUILD_TIME     __TIME__

/* Global kernel state */
static BootInfo *g_boot_info = NULL;
static bool kernel_initialized = false;
static uint64_t kernel_start_time = 0;
static uint64_t phase_times[5] = {0};

/* Forward declarations for initialization functions */
static void print_banner(void);
static void validate_boot_info(BootInfo *boot_info);
static void validate_framebuffer(BootInfo *boot_info);
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

/*
 * Main kernel entry point called from assembly
 * 
 * At this point:
 * - We're in long mode (64-bit)
 * - We have basic page tables set up
 * - We have a minimal IDT 
 * - Interrupts are disabled
 * - We have a small stack
 * - UEFI boot services are terminated
 */
void kernel_main(BootInfo *boot_info)
{
    int result;
    
    /* Store boot info globally */
    g_boot_info = boot_info;
    
    /* Validate boot information before proceeding */
    validate_boot_info(boot_info);
    
    /* Initialize early console for debugging output */
    init_early_console(boot_info);
    
    /* Print kernel banner */
    print_banner();
    
    printk(KERN_INFO "CinnamonOS kernel starting...\n");
    printk(KERN_INFO "Boot info at 0x%lx\n", (uint64_t)boot_info);
    
    /*
     * Phase 1: Core kernel subsystems
     * These must be initialized in order due to dependencies
     */
    
    printk(KERN_INFO "Phase 1: Initializing core subsystems...\n");
    phase_times[0] = get_system_time();
    
    /* Initialize memory management first - everything depends on this */
    result = init_memory_management(boot_info);
    if (result != 0) {
        panic("Failed to initialize memory management: %d", result);
    }
    printk(KERN_OK "Memory management initialized\n");
    
    /* Set up proper interrupt and exception handling */
    result = init_interrupt_handling();
    if (result != 0) {
        panic("Failed to initialize interrupt handling: %d", result);
    }
    printk(KERN_OK "Interrupt handling initialized\n");
    
    /* Initialize timing subsystem */
    result = init_timing();
    if (result != 0) {
        panic("Failed to initialize timing: %d", result);
    }
    printk(KERN_OK "Timing subsystem initialized\n");
    
    phase_times[0] = get_system_time() - phase_times[0];
    printk(KERN_INFO "Phase 1 complete in %lu ms\n", NS_TO_MS(phase_times[0]));
    
    /*
     * Phase 2: Process and scheduling subsystems
     */
    
    printk(KERN_INFO "Phase 2: Initializing process management...\n");
    phase_times[1] = get_system_time();
    
    /* Set up task scheduling */
    result = init_scheduling();
    if (result != 0) {
        panic("Failed to initialize scheduler: %d", result);
    }
    printk(KERN_OK "Scheduler initialized\n");
    
    /* Initialize process management */
    result = init_process_management();
    if (result != 0) {
        panic("Failed to initialize process management: %d", result);
    }
    printk(KERN_OK "Process management initialized\n");
    
    /* Set up IPC mechanisms */
    result = init_ipc_subsystem();
    if (result != 0) {
        panic("Failed to initialize IPC: %d", result);
    }
    printk(KERN_OK "IPC subsystem initialized\n");
    
    phase_times[1] = get_system_time() - phase_times[1];
    printk(KERN_INFO "Phase 2 complete in %lu ms\n", NS_TO_MS(phase_times[1]));
    
    /*
     * Phase 3: System call interface
     */
    
    printk(KERN_INFO "Phase 3: Initializing system call interface...\n");
    phase_times[2] = get_system_time();
    
    result = init_system_calls();
    if (result != 0) {
        panic("Failed to initialize system calls: %d", result);
    }
    printk(KERN_OK "System calls initialized\n");
    
    phase_times[2] = get_system_time() - phase_times[2];
    printk(KERN_INFO "Phase 3 complete in %lu ms\n", NS_TO_MS(phase_times[2]));
    
    /*
     * Phase 4: Optional subsystems
     */
    
    printk(KERN_INFO "Phase 4: Initializing optional subsystems...\n");
    phase_times[3] = get_system_time();
    
    /* Initialize networking stack */
    result = init_networking();
    if (result != 0) {
        printk(KERN_WARN "Networking initialization failed: %d\n", result);
        /* Non-fatal - continue without networking */
    } else {
        printk(KERN_OK "Network stack initialized\n");
    }
    
    /* Initialize security subsystem */
    result = init_security();
    if (result != 0) {
        printk(KERN_WARN "Security initialization failed: %d\n", result);
        /* Non-fatal - continue with reduced security */
    } else {
        printk(KERN_OK "Security subsystem initialized\n");
    }
    
    phase_times[3] = get_system_time() - phase_times[3];
    printk(KERN_INFO "Phase 4 complete in %lu ms\n", NS_TO_MS(phase_times[3]));
    
    /*
     * Phase 5: Enable interrupts and launch userspace
     */
    
    printk(KERN_INFO "Phase 5: Finalizing kernel startup...\n");
    phase_times[4] = get_system_time();
    
    /* Record initialization completion time */
    kernel_start_time = get_system_time();
    kernel_initialized = true;
    
    uint64_t total_init_time = kernel_start_time;
    printk(KERN_OK "Kernel initialization complete in %lu ms\n",
           NS_TO_MS(total_init_time));
    
    /* Print phase timing breakdown */
    printk(KERN_INFO "Timing breakdown - Phase 1: %lu ms, Phase 2: %lu ms, "
           "Phase 3: %lu ms, Phase 4: %lu ms\n",
           NS_TO_MS(phase_times[0]), NS_TO_MS(phase_times[1]),
           NS_TO_MS(phase_times[2]), NS_TO_MS(phase_times[3]));
    
    /* Enable interrupts - we're ready to handle them properly now */
    printk(KERN_INFO "Enabling interrupts...\n");
    asm volatile("sti");
    
    /* Launch the first userspace process (/user/init) */
    launch_init_process();
    
    /* 
     * We should never reach here - the init process takes over
     * If we do, something went wrong with process creation
     */
    panic("kernel_main() returned - init process failed to start");
}

/*
 * Print the kernel startup banner
 */
static void print_banner(void)
{
    console_clear();
    
    printk(KERN_NONE "  ____ _                                          ___  ____  \n");
    printk(KERN_NONE " / ___(_)_ __  _ __   __ _ _ __ ___   ___  _ __  / _ \/ ___|  \n");
    printk(KERN_NONE "| |   | | '_ \| '_ \ / _` | '_ ` _ \ / _ \| '_ \| | | \___ \ \n");
    printk(KERN_NONE "| |___| | | | | | | | (_| | | | | | | (_) | | | | |_| |___) | \n");
    printk(KERN_NONE "  \____|_|_| |_|_| |_|\__,_|_| |_| |_|\___/|_| |_|\___/|____/  \n");
    printk(KERN_NONE "\n");
    printk(KERN_NONE "CinnamonOS v%d.%d.%d - Built %s %s\n", 
           CINNAMON_VERSION_MAJOR, CINNAMON_VERSION_MINOR, 
           CINNAMON_VERSION_PATCH, CINNAMON_BUILD_DATE, CINNAMON_BUILD_TIME);
    printk(KERN_NONE "Open Source Microkernel Operating System\n\n");
}

/*
 * Validate boot information structure
 */
static void validate_boot_info(BootInfo *boot_info)
{
    if (!boot_info) {
        panic("Boot info is NULL");
    }
    
    /* Validate memory map */
    if (!boot_info->memory_map || boot_info->memory_map_size == 0) {
        panic("Invalid memory map in boot info");
    }
    
    /* Validate framebuffer */
    validate_framebuffer(boot_info);
    
    /* Ensure command line is null-terminated */
    boot_info->cmdline[255] = '\0';
    
    DEBUG_PRINT("Boot info validation passed\n");
}

/*
 * Validate framebuffer configuration
 */
static void validate_framebuffer(BootInfo *boot_info)
{
    if (boot_info->framebuffer_base != 0) {
        if (boot_info->framebuffer_width == 0 || 
            boot_info->framebuffer_height == 0 ||
            boot_info->framebuffer_pitch == 0) {
            panic("Invalid framebuffer parameters");
        }
        
        /* Sanity check: pitch should be at least width * bytes_per_pixel */
        if (boot_info->framebuffer_pitch < boot_info->framebuffer_width * 4) {
            printk(KERN_WARN "Suspicious framebuffer pitch: %u < %u * 4\n",
                   boot_info->framebuffer_pitch, boot_info->framebuffer_width);
        }
        
        /* Check for overlapping memory ranges */
        uint64_t fb_end = boot_info->framebuffer_base + boot_info->framebuffer_size;
        if (boot_info->initrd_base != 0 && boot_info->initrd_size != 0) {
            uint64_t initrd_end = boot_info->initrd_base + boot_info->initrd_size;
            if ((boot_info->framebuffer_base < initrd_end) && 
                (fb_end > boot_info->initrd_base)) {
                printk(KERN_WARN "Framebuffer overlaps with initrd\n");
            }
        }
    }
}

/*
 * Initialize early console output
 */
static void init_early_console(BootInfo *boot_info)
{
    console_init(boot_info->framebuffer_base,
                 boot_info->framebuffer_width,
                 boot_info->framebuffer_height,
                 boot_info->framebuffer_pitch);
    
    /* Also initialize printk logging */
    printk_init();
}

/*
 * Initialize memory management subsystem
 */
static int init_memory_management(BootInfo *boot_info)
{
    int result;
    
    /* Initialize physical page allocator using UEFI memory map */
    result = page_alloc_init(boot_info->memory_map,
                            boot_info->memory_map_size,
                            boot_info->descriptor_size);
    if (result != 0) {
        return result;
    }
    
    /* Set up virtual memory management */
    result = vmem_init(&boot_pml4, &boot_pdpt, &boot_pd);
    if (result != 0) {
        return result;
    }
    
    /* Initialize kernel heap allocator */
    result = kmalloc_init();
    if (result != 0) {
        return result;
    }
    
    /* Set up proper page tables (replace boot page tables) */
    result = paging_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

/*
 * Initialize interrupt and exception handling
 */
static int init_interrupt_handling(void)
{
    int result;
    
    /* Set up proper IDT with all handlers */
    result = irq_init();
    if (result != 0) {
        return result;
    }
    
    /* Initialize PIC/APIC */
    result = pic_init();
    if (result != 0) {
        return result;
    }
    
    /* Set up ISRs for common exceptions */
    result = isr_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

/*
 * Initialize task scheduling
 */
static int init_scheduling(void)
{
    int result;
    
    /* Initialize scheduler data structures */
    result = scheduler_init();
    if (result != 0) {
        return result;
    }
    
    /* Set up thread management */
    result = thread_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

/*
 * Initialize process management
 */
static int init_process_management(void)
{
    int result;
    
    /* Initialize process table and management */
    result = process_init();
    if (result != 0) {
        return result;
    }
    
    /* Initialize exec() and program loading */
    result = exec_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

/*
 * Initialize IPC subsystem
 */
static int init_ipc_subsystem(void)
{
    int result;
    
    /* Initialize core IPC */
    result = ipc_init();
    if (result != 0) {
        return result;
    }
    
    /* Initialize message queues */
    result = msgqueue_init();
    if (result != 0) {
        return result;
    }
    
    /* Initialize pipes */
    result = pipe_init();
    if (result != 0) {
        return result;
    }
    
    /* Initialize shared memory */
    result = shm_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

/*
 * Initialize system call interface
 */
static int init_system_calls(void)
{
    int result;
    
    /* Set up syscall dispatcher */
    result = syscall_init();
    if (result != 0) {
        return result;
    }
    
    /* Register all system calls */
    result = syscall_table_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

/*
 * Initialize timing subsystem
 */
static int init_timing(void)
{
    int result;
    
    /* Initialize system timer */
    result = timer_init();
    if (result != 0) {
        return result;
    }
    
    /* Initialize RTC */
    result = rtc_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

/*
 * Initialize networking stack
 */
static int init_networking(void)
{
    int result;
    
    /* Initialize core networking */
    result = net_init();
    if (result != 0) {
        return result;
    }
    
    /* Initialize socket layer */
    result = socket_init();
    if (result != 0) {
        /* Provide stub socket layer for compatibility */
        socket_init_stub();
        return result;
    }
    
    /* Initialize IP layer */
    result = ip_init();
    if (result != 0) {
        return result;
    }
    
    /* Initialize TCP */
    result = tcp_init();
    if (result != 0) {
        return result;
    }
    
    /* Initialize UDP */
    result = udp_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

/*
 * Initialize security subsystem
 */
static int init_security(void)
{
    int result;
    
    /* Initialize core security hooks */
    result = security_init();
    if (result != 0) {
        /* Initialize minimal security stubs */
        security_init_stub();
        return result;
    }
    
    /* Initialize integrity checking */
    result = integrity_init();
    if (result != 0) {
        return result;
    }
    
    /* Initialize sandboxing */
    result = sandbox_init();
    if (result != 0) {
        return result;
    }
    
    return 0;
}

/*
 * Launch the first userspace process (/user/init)
 */
static void launch_init_process(void)
{
    int result;
    pid_t init_pid;
    
    printk(KERN_INFO "Launching init process...\n");
    
    /* Ensure command line is safe to pass */
    if (strlen(g_boot_info->cmdline) >= 255) {
        printk(KERN_WARN "Command line too long, truncating\n");
        g_boot_info->cmdline[254] = '\0';
    }
    
    /* Create the init process */
    init_pid = process_create_user("/user/init", g_boot_info->cmdline);
    if (init_pid < 0) {
        panic("Failed to create init process: %d", init_pid);
    }
    
    printk(KERN_OK "Init process created with PID %d\n", init_pid);
    
    /* Create and start the kernel idle task */
    result = thread_create_kernel(kernel_idle_task, NULL, "idle");
    if (result < 0) {
        printk(KERN_WARN "Failed to create idle task: %d\n", result);
    }
    
    /* Start the scheduler - this will switch to init process */
    /* Note: scheduler_start() should handle the transition from this context */
    scheduler_start();
    
    /* We should never reach here */
    panic("scheduler_start() returned");
}

/*
 * Kernel idle task - runs when no other tasks are ready
 */
static void kernel_idle_task(void)
{
    printk(KERN_INFO "Kernel idle task started\n");
    
    while (1) {
        /* Enable interrupts and halt until next interrupt */
        asm volatile("sti; hlt");
        
        /* Check if there are runnable tasks */
        scheduler_yield();
    }
}

/*
 * Kernel panic handler - called for unrecoverable errors
 * This function is implemented in init/panic.c but declared here
 */
void panic(const char *fmt, ...)
{
    va_list args;
    
    /* Disable interrupts immediately */
    asm volatile("cli");
    
    /* Print panic message */
    printk(KERN_PANIC "\n*** KERNEL PANIC ***\n");
    
    va_start(args, fmt);
    vprintk(KERN_PANIC, fmt, args);
    va_end(args);
    
    printk(KERN_PANIC "\n");
    
    /* Print some debugging info */
    printk(KERN_PANIC "Kernel initialized: %s\n", 
           kernel_initialized ? "YES" : "NO");
    
    if (kernel_initialized) {
        printk(KERN_PANIC "Uptime: %lu ms\n", 
               NS_TO_MS(get_system_time() - kernel_start_time));
    }
    
    /* Dump stack trace if available */
    stack_trace_print();
    
    /* Halt the system */
    printk(KERN_PANIC "System halted.\n");
    
    while (1) {
        asm volatile("hlt");
    }
}

/*
 * Kernel information functions
 */
bool is_kernel_initialized(void)
{
    return kernel_initialized;
}

uint64_t get_kernel_uptime(void)
{
    if (!kernel_initialized) {
        return 0;
    }
    return NS_TO_MS(get_system_time() - kernel_start_time);
}

BootInfo *get_boot_info(void)
{
    return g_boot_info;
}
