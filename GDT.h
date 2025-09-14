/*
 * CinnamonOS Global Descriptor Table (GDT) Header
 * File: include/gdt.h
 */

#ifndef _CINNAMON_GDT_H
#define _CINNAMON_GDT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

//==============================================================================
// G D T   C O N S T A N T S   A N D   S E L E C T O R S
//==============================================================================

// Segment Selectors (byte offsets in GDT)
#define GDT_NULL_SEL            0x00    // Null descriptor
#define GDT_KERNEL_CS32_SEL     0x08    // 32-bit kernel code
#define GDT_KERNEL_DS32_SEL     0x10    // 32-bit kernel data
#define GDT_USER_CS32_SEL       0x18    // 32-bit user code
#define GDT_USER_DS32_SEL       0x20    // 32-bit user data
#define GDT_KERNEL_CS64_SEL     0x28    // 64-bit kernel code
#define GDT_KERNEL_DS64_SEL     0x30    // 64-bit kernel data
#define GDT_USER_CS64_SEL       0x38    // 64-bit user code
#define GDT_USER_DS64_SEL       0x40    // 64-bit user data
#define GDT_TSS_SEL             0x48    // Task State Segment (16 bytes)
#define GDT_CALL_GATE_SEL       0x58    // Call gate for syscalls
#define GDT_LDT_SEL             0x60    // Local Descriptor Table
#define GDT_SYSENTER_CS_SEL     0x68    // SYSENTER code segment
#define GDT_SYSENTER_SS_SEL     0x70    // SYSENTER stack segment
#define GDT_TLS_BASE_SEL        0x78    // Thread Local Storage base
#define GDT_PERF_COUNTER_SEL    0x80    // Performance counter segment

// RPL (Requested Privilege Level) masks
#define RPL_KERNEL              0x00    // Ring 0
#define RPL_USER                0x03    // Ring 3
#define RPL_MASK                0x03    // Mask for RPL bits

// Segment selector construction macros
#define SEGMENT_SELECTOR(index, rpl)    ((index) | (rpl))
#define USER_CODE_SELECTOR              (GDT_USER_CS64_SEL | RPL_USER)
#define USER_DATA_SELECTOR              (GDT_USER_DS64_SEL | RPL_USER)
#define KERNEL_CODE_SELECTOR            (GDT_KERNEL_CS64_SEL | RPL_KERNEL)
#define KERNEL_DATA_SELECTOR            (GDT_KERNEL_DS64_SEL | RPL_KERNEL)

// Access Rights Byte Components
#define ACC_PRESENT             0x80    // P: Present bit
#define ACC_DPL_0               0x00    // DPL: Descriptor Privilege Level 0 (kernel)
#define ACC_DPL_1               0x20    // DPL: Descriptor Privilege Level 1
#define ACC_DPL_2               0x40    // DPL: Descriptor Privilege Level 2  
#define ACC_DPL_3               0x60    // DPL: Descriptor Privilege Level 3 (user)
#define ACC_DPL_MASK            0x60    // Mask for DPL bits
#define ACC_DESCRIPTOR          0x10    // S: Descriptor type (1=code/data, 0=system)
#define ACC_CODE                0x08    // E: Executable (code segment)
#define ACC_CONFORMING          0x04    // C: Conforming code segment
#define ACC_READABLE            0x02    // R: Readable code / Writable data
#define ACC_WRITABLE            0x02    // W: Writable data segment
#define ACC_ACCESSED            0x01    // A: Accessed bit

// Flags Byte Components  
#define FLAG_GRANULARITY        0x80    // G: Granularity (0=byte, 1=4KB)
#define FLAG_SIZE32             0x40    // D/B: Default operation size (1=32-bit)
#define FLAG_LONG_MODE          0x20    // L: Long mode code segment (64-bit)
#define FLAG_AVAILABLE          0x10    // AVL: Available for software use

// System Descriptor Types
#define SYS_TSS_AVAILABLE       0x09    // Available 64-bit TSS
#define SYS_TSS_BUSY            0x0B    // Busy 64-bit TSS
#define SYS_CALL_GATE           0x0C    // Call gate
#define SYS_INTERRUPT_GATE      0x0E    // Interrupt gate
#define SYS_TRAP_GATE           0x0F    // Trap gate
#define SYS_LDT                 0x02    // Local Descriptor Table

// Stack sizes (recommended)
#define KERNEL_STACK_SIZE       (16 * 1024)    // 16KB
#define IST_STACK_SIZE          (16 * 1024)    // 16KB each
#define USER_STACK_SIZE         (8 * 1024)     // 8KB default

// TSS field offsets (for assembly access)
#define TSS_RSP0_OFFSET         4
#define TSS_RSP1_OFFSET         12
#define TSS_RSP2_OFFSET         20
#define TSS_IST1_OFFSET         36
#define TSS_IST2_OFFSET         44
#define TSS_IST3_OFFSET         52
#define TSS_IST4_OFFSET         60
#define TSS_IST5_OFFSET         68
#define TSS_IST6_OFFSET         76
#define TSS_IST7_OFFSET         84
#define TSS_IOPB_OFFSET         102

// Error codes
#define GDT_SUCCESS             0
#define GDT_ERROR_INVALID_PRIV  -1
#define GDT_ERROR_INVALID_IST   -2
#define GDT_ERROR_INVALID_PORT  -3
#define GDT_ERROR_INVALID_ADDR  -4
#define GDT_ERROR_NOT_LOADED    -5

// MSR Numbers
#define MSR_IA32_SYSENTER_CS    0x174
#define MSR_IA32_SYSENTER_ESP   0x175
#define MSR_IA32_SYSENTER_EIP   0x176
#define MSR_IA32_FS_BASE        0xC0000100
#define MSR_IA32_GS_BASE        0xC0000101
#define MSR_IA32_KERNEL_GS_BASE 0xC0000102

//==============================================================================
// G D T   S T R U C T U R E   D E F I N I T I O N S
//==============================================================================

// Standard GDT Entry structure (8 bytes)
typedef struct {
    uint16_t limit_low;         // Limit 15:0
    uint16_t base_low;          // Base 15:0
    uint8_t base_mid;           // Base 23:16
    uint8_t access;             // Access byte
    uint8_t flags_limit_high;   // Flags + Limit 19:16
    uint8_t base_high;          // Base 31:24
} __attribute__((packed)) gdt_entry_t;

// TSS Entry structure (16 bytes in 64-bit mode)
typedef struct {
    uint16_t limit_low;         // Limit 15:0
    uint16_t base_low;          // Base 15:0
    uint8_t base_mid;           // Base 23:16
    uint8_t access;             // Access byte
    uint8_t flags_limit_high;   // Flags + Limit 19:16
    uint8_t base_high;          // Base 31:24
    uint32_t base_upper;        // Base 63:32
    uint32_t reserved;          // Must be zero
} __attribute__((packed)) tss_entry_t;

// Call Gate structure (16 bytes in 64-bit mode)
typedef struct {
    uint16_t offset_low;        // Offset 15:0
    uint16_t selector;          // Target segment selector
    uint8_t param_count;        // Parameter count (0 in 64-bit)
    uint8_t access;             // Access byte
    uint16_t offset_mid;        // Offset 31:16
    uint32_t offset_high;       // Offset 63:32
    uint32_t reserved;          // Must be zero
} __attribute__((packed)) call_gate_t;

// GDT Register (GDTR) structure
typedef struct {
    uint16_t limit;             // Size of GDT - 1
    uint64_t base;              // Base address of GDT
} __attribute__((packed)) gdt_register_t;

// Task State Segment structure (64-bit)
typedef struct {
    uint32_t reserved1;         // Reserved
    uint64_t rsp0;              // Stack pointer for CPL 0
    uint64_t rsp1;              // Stack pointer for CPL 1
    uint64_t rsp2;              // Stack pointer for CPL 2
    uint64_t reserved2;         // Reserved
    uint64_t ist1;              // IST 1 - Double fault
    uint64_t ist2;              // IST 2 - NMI
    uint64_t ist3;              // IST 3 - Machine check
    uint64_t ist4;              // IST 4 - Debug exceptions
    uint64_t ist5;              // IST 5 - General protection
    uint64_t ist6;              // IST 6 - Stack fault
    uint64_t ist7;              // IST 7 - Critical interrupts
    uint64_t reserved3;         // Reserved
    uint16_t reserved4;         // Reserved
    uint16_t iopb_offset;       // I/O Permission Bitmap offset
} __attribute__((packed)) tss64_t;

// Stack configuration structure
typedef struct {
    void* kernel_stack;         // Main kernel stack (RSP0)
    void* ist_stacks[7];        // IST stacks 1-7
    size_t stack_size;          // Size of each stack
} gdt_stack_config_t;

// GDT configuration structure
typedef struct {
    bool smp_enabled;           // SMP support
    bool syscall_gate_enabled;  // Call gate support
    bool sysenter_enabled;      // SYSENTER/SYSEXIT support
    bool tls_enabled;           // Thread-local storage support
    bool debug_mode;            // Debug validation enabled
    uint32_t io_bitmap_size;    // I/O permission bitmap size
} gdt_config_t;

// Runtime statistics structure
typedef struct {
    uint64_t total_context_switches;
    uint64_t total_privilege_transitions;
    uint64_t user_to_kernel_transitions;
    uint64_t kernel_to_user_transitions;
    uint64_t io_permission_changes;
    uint64_t tss_updates;
    uint64_t validation_checks;
    uint64_t errors;
} gdt_statistics_t;

//==============================================================================
// A S S E M B L Y   F U N C T I O N   P R O T O T Y P E S
//==============================================================================

// Core GDT functions (implemented in assembly)
extern void gdt_initialize(void);
extern void gdt_full_initialize(void* kernel_stack, void* ist_stacks[], void* syscall_handler);
extern int gdt_validate(void);
extern void gdt_switch_to_user(uint64_t user_rsp, uint64_t user_rip, uint64_t user_rflags);
extern int gdt_get_privilege_level(void);

// Stack management functions
extern int gdt_set_privilege_stack(int privilege_level, void* stack_pointer);
extern int gdt_set_interrupt_stack(int ist_number, void* stack_pointer);

// I/O permission functions  
extern int gdt_set_io_permission(uint16_t port, int permission);
extern int gdt_set_io_range_permission(uint16_t start_port, uint16_t end_port, int permission);
extern void gdt_deny_all_io(void);
extern void gdt_allow_basic_io(void);

// Advanced functions
extern void gdt_setup_sysenter(void* syscall_handler, void* syscall_stack);
extern int gdt_setup_tls(uint64_t fs_base, uint64_t gs_base);
extern void gdt_update_tss_base(void* new_tss);
extern void gdt_reload_segments(void);

// Performance and utility functions
extern uint64_t gdt_get_context_switches(void);
extern uint64_t gdt_get_privilege_transitions(void);
extern void gdt_record_context_switch(void);
extern void gdt_record_privilege_transition(void);
extern void gdt_emergency_reset(void);
extern int gdt_init_cpu(int cpu_id, void* cpu_tss, void* cpu_stacks[]);

// TLS functions
extern void gdt_set_tls_base(uint64_t tls_base);

// External symbols from assembly
extern gdt_entry_t gdt_table[];
extern gdt_register_t gdt_register;
extern tss64_t tss;
extern uint8_t tss_iopb[];
extern uint64_t context_switch_count;
extern uint64_t privilege_transition_count;

//==============================================================================
// I N L I N E   H E L P E R   F U N C T I O N S
//==============================================================================

// Get current code segment
static inline uint16_t gdt_get_cs(void) {
    uint16_t cs;
    __asm__ volatile ("movw %%cs, %0" : "=r" (cs));
    return cs;
}

// Get current data segment
static inline uint16_t gdt_get_ds(void) {
    uint16_t ds;
    __asm__ volatile ("movw %%ds, %0" : "=r" (ds));
    return ds;
}

// Get Task Register
static inline uint16_t gdt_get_tr(void) {
    uint16_t tr;
    __asm__ volatile ("str %0" : "=r" (tr));
    return tr;
}

// Check if running in user mode
static inline bool gdt_in_user_mode(void) {
    return (gdt_get_cs() & RPL_MASK) == RPL_USER;
}

// Check if running in kernel mode
static inline bool gdt_in_kernel_mode(void) {
    return (gdt_get_cs() & RPL_MASK) == RPL_KERNEL;
}

// Create segment selector with RPL
static inline uint16_t gdt_make_selector(uint16_t index, uint8_t rpl) {
    return (index & ~RPL_MASK) | (rpl & RPL_MASK);
}

// Extract RPL from selector
static inline uint8_t gdt_get_rpl(uint16_t selector) {
    return selector & RPL_MASK;
}

// Read MSR
static inline uint64_t read_msr(uint32_t msr) {
    uint32_t low, high;
    __asm__ volatile ("rdmsr" : "=a" (low), "=d" (high) : "c" (msr));
    return ((uint64_t)high << 32) | low;
}

// Write MSR
static inline void write_msr(uint32_t msr, uint64_t value) {
    uint32_t low = value & 0xFFFFFFFF;
    uint32_t high = value >> 32;
    __asm__ volatile ("wrmsr" : : "a" (low), "d" (high), "c" (msr));
}

// Enable interrupts
static inline void sti(void) {
    __asm__ volatile ("sti");
}

// Disable interrupts
static inline void cli(void) {
    __asm__ volatile ("cli");
}

// Halt processor
static inline void hlt(void) {
    __asm__ volatile ("hlt");
}

// Swap GS register (for user/kernel transitions)
static inline void swapgs(void) {
    __asm__ volatile ("swapgs");
}

//==============================================================================
// M A C R O S   F O R   D E S C R I P T O R   C R E A T I O N
//==============================================================================

// Create access byte
#define GDT_ACCESS_BYTE(present, dpl, desc_type, executable, conforming, rw, accessed) \
    (((present) ? ACC_PRESENT : 0) | \
     (((dpl) & 3) << 5) | \
     ((desc_type) ? ACC_DESCRIPTOR : 0) | \
     ((executable) ? ACC_CODE : 0) | \
     ((conforming) ? ACC_CONFORMING : 0) | \
     ((rw) ? ACC_READABLE : 0) | \
     ((accessed) ? ACC_ACCESSED : 0))

// Create flags byte  
#define GDT_FLAGS_BYTE(granularity, size32, long_mode, available, limit_high) \
    (((granularity) ? FLAG_GRANULARITY : 0) | \
     ((size32) ? FLAG_SIZE32 : 0) | \
     ((long_mode) ? FLAG_LONG_MODE : 0) | \
     ((available) ? FLAG_AVAILABLE : 0) | \
     ((limit_high) & 0x0F))

// Create GDT entry
#define GDT_ENTRY(base, limit, access, flags) { \
    .limit_low = (limit) & 0xFFFF, \
    .base_low = (base) & 0xFFFF, \
    .base_mid = ((base) >> 16) & 0xFF, \
    .access = (access), \
    .flags_limit_high = (((flags) & 0xF0) | (((limit) >> 16) & 0x0F)), \
    .base_high = ((base) >> 24) & 0xFF \
}

//==============================================================================
// E R R O R   H A N D L I N G   M A C R O S
//==============================================================================

#define GDT_CHECK_PRIVILEGE(level) \
    do { if ((level) < 0 || (level) > 3) return GDT_ERROR_INVALID_PRIV; } while(0)

#define GDT_CHECK_IST(ist) \
    do { if ((ist) < 1 || (ist) > 7) return GDT_ERROR_INVALID_IST; } while(0)

#define GDT_CHECK_PORT(port) \
    do { if ((port) > 65535) return GDT_ERROR_INVALID_PORT; } while(0)

#define GDT_CHECK_ALIGNMENT(addr, align) \
    do { if (((uintptr_t)(addr) & ((align) - 1)) != 0) return GDT_ERROR_INVALID_ADDR; } while(0)

#define GDT_CHECK_NULL(ptr) \
    do { if ((ptr) == NULL) return GDT_ERROR_INVALID_ADDR; } while(0)

//==============================================================================
// D E B U G   M A C R O S
//==============================================================================

#ifdef GDT_DEBUG
    #include <stdio.h>
    #define GDT_DEBUG_PRINT(fmt, ...) printf("[GDT DEBUG] " fmt "\n", ##__VA_ARGS__)
    #define GDT_ASSERT(cond) do { if (!(cond)) { \
        printf("[GDT ASSERT] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        while(1) hlt(); \
    } } while(0)
    #define GDT_TRACE() GDT_DEBUG_PRINT("TRACE: %s:%d %s", __FILE__, __LINE__, __func__)
#else
    #define GDT_DEBUG_PRINT(fmt, ...)
    #define GDT_ASSERT(cond)
    #define GDT_TRACE()
#endif

//==============================================================================
// C   C O N V E N I E N C E   F U N C T I O N S (to be implemented separately)
//==============================================================================

// Initialization functions
int gdt_quick_setup(void);
int gdt_kernel_init(void* memory_pool, size_t pool_size);
int gdt_init_with_config(const gdt_config_t* config, const gdt_stack_config_t* stacks);

// Stack management helpers
void* gdt_allocate_stack(size_t size);
void gdt_free_stack(void* stack);
int gdt_setup_kernel_stacks(const gdt_stack_config_t* config);

// I/O permission helpers (wrappers around assembly functions)
static inline int gdt_allow_port(uint16_t port) {
    return gdt_set_io_permission(port, 0);  // 0 = allow
}

static inline int gdt_deny_port(uint16_t port) {
    return gdt_set_io_permission(port, 1);  // 1 = deny
}

static inline int gdt_allow_port_range(uint16_t start, uint16_t end) {
    return gdt_set_io_range_permission(start, end, 0);  // 0 = allow
}

static inline int gdt_deny_port_range(uint16_t start, uint16_t end) {
    return gdt_set_io_range_permission(start, end, 1);  // 1 = deny
}

// User mode transition helpers
int gdt_create_user_thread(void* entry_point, void* stack_base, size_t stack_size);
int gdt_switch_privilege_level(int new_level);

// Debug and validation functions
void gdt_dump_table(void);
void gdt_dump_tss(void);
bool gdt_is_valid_selector(uint16_t selector);
const char* gdt_get_selector_name(uint16_t selector);

// Performance monitoring
void gdt_enable_performance_counters(void);
const gdt_statistics_t* gdt_get_statistics(void);
void gdt_reset_statistics(void);
void gdt_print_statistics(void);

// Advanced features
int gdt_comprehensive_validation(void);
int gdt_setup_per_cpu(int cpu_id, void* cpu_tss, void* cpu_stacks[]);
int gdt_apply_security_policy(void);
int gdt_setup_syscall_interface(void* syscall_handler, void* syscall_stack);

// Thread-local storage helpers
int gdt_set_thread_area(void* tls_base);
int gdt_get_thread_area(void** tls_base_out);

//==============================================================================
// B O O T L O A D E R   I N T E G R A T I O N   H E L P E R S
//==============================================================================


// Quick initialization for bootloader
static inline void gdt_bootloader_init(void) {
    gdt_initialize();
    gdt_validate();
    gdt_deny_all_io();
    gdt_allow_basic_io();
}

//==============================================================================
// C O M P I L E   T I M E   A S S E R T I O N S
//==============================================================================

// Ensure structures are correctly sized
_Static_assert(sizeof(gdt_entry_t) == 8, "GDT entry must be 8 bytes");
_Static_assert(sizeof(tss_entry_t) == 16, "TSS entry must be 16 bytes in 64-bit mode");
_Static_assert(sizeof(call_gate_t) == 16, "Call gate must be 16 bytes in 64-bit mode");
_Static_assert(sizeof(gdt_register_t) == 10, "GDTR must be 10 bytes");

// Ensure selectors are correctly defined
_Static_assert(GDT_KERNEL_CS64_SEL == 0x28, "Kernel CS64 selector mismatch");
_Static_assert(GDT_USER_CS64_SEL == 0x38, "User CS64 selector mismatch");
_Static_assert(GDT_TSS_SEL == 0x48, "TSS selector mismatch");

// Ensure RPL values are correct
_Static_assert(RPL_KERNEL == 0, "Kernel RPL must be 0");
_Static_assert(RPL_USER == 3, "User RPL must be 3");

#endif // _CINNAMON_GDT_H
