// kernel/init/panic.c
// IMPORTANT: This is more of a draft/placeholder and must be redone near the end of the kernel development

#include <init.h>
#include <mm.h>
#include <console.h>
#include <printk.h>
#include <types.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#define PANIC_CRITICAL  0
#define PANIC_SEVERE    1
#define PANIC_MODERATE  2

#define PANIC_MSG_MAX 512
#define PANIC_STACK_FRAMES 16

#define RECOVERY_MAGIC 0xDEADBEEF
#define RECOVERY_VERSION 1
#define RECOVERY_HANDOFF_ADDR 0x9000
#define RECOVERY_SIGNATURE_ADDR 0x8F00
#define RECOVERY_SIGNATURE_MAGIC 0xC1AE4302
#define RECOVERY_TEST_ADDR 0x9F00

typedef struct {
    _Atomic bool in_panic;
    _Atomic uint32_t panic_count;
    _Atomic uint64_t last_panic_time;
    char last_message[PANIC_MSG_MAX];
    uint64_t stack_trace[PANIC_STACK_FRAMES];
} panic_state_t;

static panic_state_t g_panic_state = {
    .in_panic = false,
    .panic_count = 0,
    .last_panic_time = 0,
    .last_message = {0},
    .stack_trace = {0}
};

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t entry_point;
    uint32_t checksum;
} recovery_signature_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t panic_time;
    uint32_t panic_level;
    uint32_t cpu_id;
    char panic_message[PANIC_MSG_MAX];
    uint64_t stack_trace[PANIC_STACK_FRAMES];
    uint64_t memory_map_addr;
    uint64_t framebuffer_addr;
    uint32_t fb_width, fb_height, fb_pitch;
} recovery_handoff_t;

static void panic_internal(int level, const char *fmt, va_list args);
static void capture_stack_trace(uint64_t *trace, int max_frames);
static bool is_kernel_infrastructure_intact(void);
static void attempt_graceful_shutdown(void);
static void handoff_to_recovery(int panic_level, const char *message) __attribute__((noreturn));
static void emergency_console_init(void);
static void emergency_print(const char *str);
static void emergency_vga_print(const char *str);
static void halt_all_cpus(void) __attribute__((noreturn));
static uint32_t get_current_cpu_id(void);
static bool is_recovery_accessible(void);
static bool safe_memory_read(uint64_t addr, void *dest, size_t size);

extern uint64_t get_system_time(void);
extern BootInfo *get_boot_info(void);
extern bool are_interrupts_enabled(void);
extern void disable_interrupts(void);
extern void memory_barrier(void);
extern bool is_kernel_initialized(void);
extern void emergency_serial_print(const char *str);
extern void init_emergency_serial(void);

void panic(const char *fmt, ...) __attribute__((noreturn));
void kernel_panic_level(int level, const char *fmt, ...) __attribute__((noreturn));

void panic(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    panic_internal(PANIC_CRITICAL, fmt, args);
    va_end(args);
}

void kernel_panic_level(int level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    panic_internal(level, fmt, args);
    va_end(args);
}

void kernel_warning(const char *fmt, ...)
{
    va_list args;
    char buffer[PANIC_MSG_MAX];
    
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    
    printk(KERN_WARN "KERNEL WARNING: %s\n", buffer);
    
    uint32_t panic_count = __atomic_load_n(&g_panic_state.panic_count, __ATOMIC_SEQ_CST);
    if (panic_count > 5) {
        panic("Too many kernel warnings - system unstable: %s", buffer);
    }
}

static void panic_internal(int level, const char *fmt, va_list args)
{
    char message[PANIC_MSG_MAX];
    uint64_t panic_time;
    uint32_t cpu_id;
    
    bool already_panicking = __atomic_exchange_n(&g_panic_state.in_panic, true, __ATOMIC_SEQ_CST);
    if (already_panicking) {
        static _Atomic bool in_double_panic = false;
        if (__atomic_exchange_n(&in_double_panic, true, __ATOMIC_SEQ_CST)) {
            disable_interrupts();
            while (1) {
                asm volatile("cli; hlt" ::: "memory");
            }
        }
        
        emergency_print("\nDOUBLE PANIC - RECURSIVE PANIC DETECTED!\n");
        emergency_print("System is critically unstable - handing off to recovery immediately\n");
        handoff_to_recovery(PANIC_CRITICAL, "Double panic - recursive failure");
    }
    
    disable_interrupts();
    memory_barrier();
    
    panic_time = get_system_time();
    cpu_id = get_current_cpu_id();
    
    vsnprintf(message, sizeof(message), fmt, args);
    
    __atomic_fetch_add(&g_panic_state.panic_count, 1, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_panic_state.last_panic_time, panic_time, __ATOMIC_SEQ_CST);
    
    memory_barrier();
    strncpy(g_panic_state.last_message, message, PANIC_MSG_MAX - 1);
    g_panic_state.last_message[PANIC_MSG_MAX - 1] = '\0';
    
    capture_stack_trace(g_panic_state.stack_trace, PANIC_STACK_FRAMES);
    memory_barrier();
    
    emergency_console_init();
    
    emergency_print("\n");
    emergency_print("================================\n");
    emergency_print("   CINNAMON OS KERNEL PANIC     \n");
    emergency_print("================================\n");
    emergency_print("\n");
    
    emergency_print("PANIC: ");
    emergency_print(message);
    emergency_print("\n\n");
    
    emergency_print("System Information:\n");
    emergency_print("  CPU: ");
    if (cpu_id != 0xFFFFFFFF) {
        char cpu_str[32];
        snprintf(cpu_str, sizeof(cpu_str), "%" PRIu32, cpu_id);
        emergency_print(cpu_str);
    } else {
        emergency_print("Unknown");
    }
    emergency_print("\n");
    
    emergency_print("  Time: ");
    if (panic_time > 0) {
        char time_str[64];
        snprintf(time_str, sizeof(time_str), "%" PRIu64 " ms since boot", panic_time / 1000000);
        emergency_print(time_str);
    } else {
        emergency_print("Timer unavailable");
    }
    emergency_print("\n");
    
    char panic_count_str[32];
    uint32_t count = __atomic_load_n(&g_panic_state.panic_count, __ATOMIC_SEQ_CST);
    snprintf(panic_count_str, sizeof(panic_count_str), "  Panic count: %" PRIu32 "\n", count);
    emergency_print(panic_count_str);
    
    emergency_print("  Severity: ");
    switch (level) {
        case PANIC_CRITICAL:
            emergency_print("CRITICAL - System cannot continue");
            break;
        case PANIC_SEVERE:
            emergency_print("SEVERE - Major subsystem failure");
            break;
        case PANIC_MODERATE:
            emergency_print("MODERATE - Recoverable error");
            break;
        default:
            emergency_print("UNKNOWN");
            break;
    }
    emergency_print("\n\n");
    
    emergency_print("Stack trace:\n");
    memory_barrier();
    for (int i = 0; i < PANIC_STACK_FRAMES && g_panic_state.stack_trace[i] != 0; i++) {
        char addr_str[32];
        snprintf(addr_str, sizeof(addr_str), "  [%d] 0x%016" PRIx64 "\n", i, g_panic_state.stack_trace[i]);
        emergency_print(addr_str);
    }
    emergency_print("\n");
    
    bool kernel_intact = is_kernel_infrastructure_intact();
    bool recovery_available = is_recovery_accessible();
    
    emergency_print("System Analysis:\n");
    emergency_print("  Kernel infrastructure: ");
    emergency_print(kernel_intact ? "INTACT" : "DAMAGED");
    emergency_print("\n");
    emergency_print("  Recovery system: ");
    emergency_print(recovery_available ? "AVAILABLE" : "NOT AVAILABLE");
    emergency_print("\n\n");
    
    if (level == PANIC_CRITICAL || !kernel_intact) {
        if (recovery_available) {
            emergency_print("CRITICAL FAILURE - Handing off to recovery system...\n");
            emergency_print("Recovery will attempt to restore system from disk\n");
            handoff_to_recovery(level, message);
        } else {
            emergency_print("CRITICAL FAILURE - No recovery system available\n");
            emergency_print("System halted - manual intervention required\n");
            emergency_print("Please check bootloader and recovery partition\n");
        }
        halt_all_cpus();
    } else if (level == PANIC_SEVERE) {
        if (is_kernel_initialized()) {
            emergency_print("SEVERE ERROR - Attempting graceful shutdown...\n");
            attempt_graceful_shutdown();
        }
        
        if (recovery_available) {
            emergency_print("Graceful shutdown failed - using recovery system\n");
            handoff_to_recovery(level, message);
        } else {
            emergency_print("No recovery available - system halted\n");
        }
        halt_all_cpus();
    } else {
        emergency_print("MODERATE ERROR - System may be able to continue\n");
        emergency_print("Attempting to isolate failure and continue...\n");
        emergency_print("Continuing with reduced functionality\n");
        emergency_print("Check system logs for details\n\n");
        
        __atomic_store_n(&g_panic_state.in_panic, false, __ATOMIC_SEQ_CST);
        return;
    }
}

static void capture_stack_trace(uint64_t *trace, int max_frames)
{
    for (int i = 0; i < max_frames; i++) {
        trace[i] = 0;
    }
    
    uint64_t rip = 0;
    asm volatile(
        "call 1f\n\t"
        "1: pop %0"
        : "=r" (rip)
        :
        : "memory"
    );
    
    if (max_frames > 0) {
        trace[0] = rip;
    }
    
    uint64_t *rbp;
    asm volatile("movq %%rbp, %0" : "=r" (rbp));
    
    for (int i = 1; i < max_frames && rbp != NULL; i++) {
        uint64_t frame_data[2];
        if (!safe_memory_read((uint64_t)rbp, frame_data, sizeof(frame_data))) {
            break;
        }
        
        uint64_t return_addr = frame_data[1];
        if (return_addr < 0x1000 || return_addr > 0x7FFFFFFFFFFF) {
            break;
        }
        
        trace[i] = return_addr;
        
        uint64_t *next_rbp = (uint64_t *)frame_data[0];
        
        if (next_rbp <= rbp || (uint64_t)next_rbp < 0x1000) {
            break;
        }
        
        rbp = next_rbp;
    }
}

static bool is_kernel_infrastructure_intact(void)
{
    extern char kernel_start;
    volatile char test = kernel_start;
    (void)test;
    
    char test_buffer[64];
    memset(test_buffer, 0xAA, sizeof(test_buffer));
    for (size_t i = 0; i < sizeof(test_buffer); i++) {
        if (test_buffer[i] != (char)0xAA) {
            return false;
        }
    }
    
    volatile uint32_t atomic_test = 42;
    uint32_t old_val = __atomic_exchange_n(&atomic_test, 84, __ATOMIC_SEQ_CST);
    if (old_val != 42 || atomic_test != 84) {
        return false;
    }
    
    return true;
}

static void attempt_graceful_shutdown(void)
{
    emergency_print("Attempting graceful shutdown...\n");
    emergency_print("Sending termination signals to processes...\n");
    
    uint64_t start_time = get_system_time();
    uint64_t timeout_ns = 5000000000ULL;
    
    if (start_time > 0) {
        while ((get_system_time() - start_time) < timeout_ns) {
            asm volatile("pause" ::: "memory");
            asm volatile("hlt" ::: "memory");
        }
    } else {
        for (volatile uint32_t i = 0; i < 50000000; i++) {
            if (i % 10000 == 0) {
                asm volatile("hlt" ::: "memory");
            }
            asm volatile("pause" ::: "memory");
        }
    }
    
    emergency_print("Graceful shutdown timeout - forcing halt\n");
}

static void handoff_to_recovery(int panic_level, const char *message)
{
    recovery_handoff_t *handoff = (recovery_handoff_t *)RECOVERY_HANDOFF_ADDR;
    BootInfo *boot_info = get_boot_info();
    
    emergency_print("Preparing recovery handoff...\n");
    
    memset((void *)handoff, 0, sizeof(recovery_handoff_t));
    
    handoff->magic = RECOVERY_MAGIC;
    handoff->version = RECOVERY_VERSION;
    handoff->panic_time = __atomic_load_n(&g_panic_state.last_panic_time, __ATOMIC_SEQ_CST);
    handoff->panic_level = panic_level;
    handoff->cpu_id = get_current_cpu_id();
    
    strncpy(handoff->panic_message, message, PANIC_MSG_MAX - 1);
    handoff->panic_message[PANIC_MSG_MAX - 1] = '\0';
    
    memory_barrier();
    for (int i = 0; i < PANIC_STACK_FRAMES; i++) {
        handoff->stack_trace[i] = g_panic_state.stack_trace[i];
    }
    memory_barrier();
    
    if (boot_info) {
        handoff->framebuffer_addr = boot_info->framebuffer_base;
        handoff->fb_width = boot_info->framebuffer_width;
        handoff->fb_height = boot_info->framebuffer_height;
        handoff->fb_pitch = boot_info->framebuffer_pitch;
        handoff->memory_map_addr = (uint64_t)boot_info->memory_map;
    }
    
    asm volatile("mfence" ::: "memory");
    memory_barrier();
    
    emergency_print("Recovery handoff prepared at 0x");
    char addr_str[32];
    snprintf(addr_str, sizeof(addr_str), "%" PRIx64, (uint64_t)RECOVERY_HANDOFF_ADDR);
    emergency_print(addr_str);
    emergency_print("\n");
    
    recovery_signature_t recovery_sig;
    uint32_t recovery_entry_addr = 0x8000;
    
    if (safe_memory_read(RECOVERY_SIGNATURE_ADDR, &recovery_sig, sizeof(recovery_sig))) {
        if (recovery_sig.magic == RECOVERY_SIGNATURE_MAGIC && 
            recovery_sig.entry_point >= 0x8000 && 
            recovery_sig.entry_point <= 0x100000) {
            recovery_entry_addr = recovery_sig.entry_point;
        }
    }
    
    emergency_print("Transferring control to recovery system at 0x");
    snprintf(addr_str, sizeof(addr_str), "%" PRIx32, recovery_entry_addr);
    emergency_print(addr_str);
    emergency_print("...\n");
    
    typedef void (*recovery_entry_t)(void);
    recovery_entry_t recovery_entry = (recovery_entry_t)(uintptr_t)recovery_entry_addr;
    
    asm volatile("cli");
    recovery_entry();
    
    emergency_print("ERROR: Recovery failed to take control!\n");
    halt_all_cpus();
}

static void emergency_console_init(void)
{
    BootInfo *boot_info = get_boot_info();
    if (!boot_info || boot_info->framebuffer_base == 0) {
        init_emergency_serial();
    }
}

static void emergency_print(const char *str)
{
    static bool printk_failed = false;
    if (!printk_failed) {
        int result = printk("%s", str);
        if (result >= 0) {
            return;
        }
        printk_failed = true;
    }
    
    static bool vga_failed = false;
    if (!vga_failed) {
        emergency_vga_print(str);
        return;
    }
    
    emergency_serial_print(str);
}

static void emergency_vga_print(const char *str)
{
    static uint16_t vga_offset = 0;
    static bool vga_accessible = true;
    
    if (!vga_accessible) {
        return;
    }
    
    uint16_t test_val;
    if (!safe_memory_read(0xB8000, &test_val, sizeof(uint16_t))) {
        vga_accessible = false;
        return;
    }
    
    volatile uint16_t *vga_buffer = (volatile uint16_t *)0xB8000;
    uint8_t color = 0x4F;
    
    for (size_t i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\n') {
            vga_offset = ((vga_offset / 80) + 1) * 80;
            if (vga_offset >= 80 * 25) {
                vga_offset = 0;
            }
        } else {
            vga_buffer[vga_offset] = ((uint16_t)color << 8) | (uint8_t)str[i];
            vga_offset++;
            if (vga_offset >= 80 * 25) {
                vga_offset = 0;
            }
        }
    }
}

static void halt_all_cpus(void)
{
    emergency_print("Halting all CPUs...\n");
    
    disable_interrupts();
    
    uint32_t eax, ebx, ecx, edx;
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    
    if (edx & (1 << 5)) {
        uint32_t msr_low, msr_high;
        asm volatile(
            "rdmsr"
            : "=a"(msr_low), "=d"(msr_high)
            : "c"(0x1B)
        );
        
        uint64_t apic_base_msr = ((uint64_t)msr_high << 32) | msr_low;
        
        if (apic_base_msr & (1ULL << 11)) {
            uint64_t apic_base = apic_base_msr & 0xFFFFF000ULL;
            
            uint32_t test_read;
            if (!safe_memory_read(apic_base + 0x300, &test_read, sizeof(uint32_t))) {
                emergency_print("APIC registers not accessible - halting local CPU only\n");
                goto halt_current_cpu;
            }
            
            volatile uint32_t *icr_low = (volatile uint32_t *)(apic_base + 0x300);
            volatile uint32_t *icr_high = (volatile uint32_t *)(apic_base + 0x310);
            
            *icr_high = 0;
            memory_barrier();
            *icr_low = 0x000C4500;
            memory_barrier();
            
            volatile uint32_t status;
            int timeout = 10000;
            do {
                status = *icr_low;
                timeout--;
            } while ((status & (1 << 12)) && timeout > 0);
            
            if (timeout == 0) {
                emergency_print("APIC IPI delivery timeout - halting local CPU only\n");
            }
        }
    }
    
halt_current_cpu:
    while (1) {
        asm volatile("cli; hlt" ::: "memory");
    }
}

static uint32_t get_current_cpu_id(void)
{
    uint32_t apic_id = 0;
    
    uint32_t eax, ebx, ecx, edx;
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    
    if (!(edx & (1 << 5))) {
        return 0xFFFFFFFF;
    }
    
    uint32_t msr_low, msr_high;
    asm volatile(
        "rdmsr"
        : "=a"(msr_low), "=d"(msr_high)
        : "c"(0x1B)
    );
    
    uint64_t apic_base_msr = ((uint64_t)msr_high << 32) | msr_low;
    
    if (!(apic_base_msr & (1ULL << 11))) {
        return 0xFFFFFFFF;
    }
    
    uint64_t apic_base = apic_base_msr & 0xFFFFF000ULL;
    uint32_t apic_id_raw;
    
    if (!safe_memory_read(apic_base + 0x20, &apic_id_raw, sizeof(uint32_t))) {
        return 0xFFFFFFFF;
    }
    
    apic_id = (apic_id_raw >> 24) & 0xFF;
    return apic_id;
}

static bool is_recovery_accessible(void)
{
    recovery_signature_t local_sig;
    
    if (!safe_memory_read(RECOVERY_SIGNATURE_ADDR, &local_sig, sizeof(recovery_signature_t))) {
        return false;
    }
    
    if (local_sig.magic != RECOVERY_SIGNATURE_MAGIC) {
        return false;
    }
    
    if (local_sig.entry_point < 0x8000 || local_sig.entry_point > 0x100000) {
        return false;
    }
    
    uint32_t test_value = 0xDEADBEEF;
    uint32_t old_val;
    
    if (!safe_memory_read(RECOVERY_TEST_ADDR, &old_val, sizeof(uint32_t))) {
        return false;
    }
    
    volatile uint32_t *test_addr = (uint32_t *)RECOVERY_TEST_ADDR;
    *test_addr = test_value;
    memory_barrier();
    
    bool writable = (*test_addr == test_value);
    *test_addr = old_val;
    memory_barrier();
    
    return writable;
}

static bool safe_memory_read(uint64_t addr, void *dest, size_t size)
{
    if (addr < 0x1000 || addr > 0x7FFFFFFFFFFF) {
        return false;
    }
    
    if (addr + size < addr) {
        return false;
    }
    
    char *src = (char *)addr;
    char *dst = (char *)dest;
    
    for (size_t i = 0; i < size; i++) {
        dst[i] = src[i];
    }
    
    memory_barrier();
    return true;
}

uint32_t get_panic_count(void)
{
    return __atomic_load_n(&g_panic_state.panic_count, __ATOMIC_SEQ_CST);
}

const char *get_last_panic_message(void)
{
    memory_barrier();
    return g_panic_state.last_message;
}

uint64_t get_last_panic_time(void)
{
    return __atomic_load_n(&g_panic_state.last_panic_time, __ATOMIC_SEQ_CST);
}

bool is_system_panicking(void)
{
    return __atomic_load_n(&g_panic_state.in_panic, __ATOMIC_SEQ_CST);
}

void reset_panic_state(void)
{
    __atomic_store_n(&g_panic_state.in_panic, false, __ATOMIC_SEQ_CST);
    memory_barrier();
    memset(g_panic_state.last_message, 0, PANIC_MSG_MAX);
    memset((void *)g_panic_state.stack_trace, 0, sizeof(g_panic_state.stack_trace));
    memory_barrier();
}

void store_panic_to_disk(void)
{
    asm volatile("mfence" ::: "memory");
}
