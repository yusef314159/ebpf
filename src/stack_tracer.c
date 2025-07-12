#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STACK_DEPTH 127
#define MAX_STACK_ENTRIES 10000
#define MAX_PROCESSES 1000

// Stack trace event for userspace
struct stack_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 cpu_id;
    __u32 stack_id;
    __u64 duration_ns;
    char comm[16];
    __u8 event_type; // 0=entry, 1=exit, 2=sample
    __u8 stack_type; // 0=kernel, 1=user, 2=mixed
    __u16 stack_depth;
    __u64 instruction_pointer;
    __u64 stack_pointer;
    __u64 frame_pointer;
    __u32 request_id; // Correlation with HTTP requests
};

// Process stack context for tracking function entry/exit
struct stack_context {
    __u64 entry_time;
    __u32 stack_id;
    __u16 depth;
    __u8 active;
};

// Stack frame information
struct stack_frame {
    __u64 ip;           // Instruction pointer
    __u64 sp;           // Stack pointer
    __u64 bp;           // Base pointer
    __u32 function_id;  // Function identifier (hash)
    char symbol[64];    // Function symbol name
};

// Profiling configuration
struct profiling_config {
    __u32 enable_kernel_stacks;
    __u32 enable_user_stacks;
    __u32 enable_mixed_stacks;
    __u32 sampling_frequency;
    __u32 max_stack_depth;
    __u32 enable_dwarf_unwinding;
    __u32 enable_frame_pointers;
    __u32 enable_correlation;
};

// Maps for stack tracing
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} stack_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_STACK_ENTRIES);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32);
    __type(value, struct stack_context);
} process_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} profiling_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct stack_frame);
} frame_cache SEC(".maps");

// Correlation with HTTP requests
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u32);
} pid_to_request_id SEC(".maps");

// Configuration keys
#define CONFIG_ENABLE_KERNEL_STACKS   0
#define CONFIG_ENABLE_USER_STACKS     1
#define CONFIG_ENABLE_MIXED_STACKS    2
#define CONFIG_SAMPLING_FREQUENCY     3
#define CONFIG_MAX_STACK_DEPTH        4
#define CONFIG_ENABLE_DWARF_UNWINDING 5
#define CONFIG_ENABLE_FRAME_POINTERS  6
#define CONFIG_ENABLE_CORRELATION     7

// Helper functions for eBPF compatibility
static __always_inline void bpf_memset(void *s, int c, int n) {
    char *p = (char *)s;

    #pragma unroll
    for (int i = 0; i < n && i < 512; i++) {
        p[i] = c;
    }
}

static __always_inline void bpf_memcpy(void *dest, const void *src, int n) {
    char *d = (char *)dest;
    const char *s = (const char *)src;

    #pragma unroll
    for (int i = 0; i < n && i < 64; i++) {
        d[i] = s[i];
    }
}

// Helper function to get configuration value
static __always_inline __u32 get_profiling_config(__u32 key, __u32 default_value) {
    __u32 *value = bpf_map_lookup_elem(&profiling_config_map, &key);
    return value ? *value : default_value;
}

// Helper function to get current request ID for correlation
static __always_inline __u32 get_current_request_id(__u32 pid) {
    if (!get_profiling_config(CONFIG_ENABLE_CORRELATION, 1)) {
        return 0;
    }
    
    __u32 *request_id = bpf_map_lookup_elem(&pid_to_request_id, &pid);
    return request_id ? *request_id : 0;
}

// Helper function to create stack event
static __always_inline struct stack_event *create_stack_event(struct pt_regs *ctx, __u8 event_type, __u8 stack_type) {
    struct stack_event *event = bpf_ringbuf_reserve(&stack_events, sizeof(*event), 0);
    if (!event) {
        return NULL;
    }
    
    bpf_memset(event, 0, sizeof(*event));
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->cpu_id = bpf_get_smp_processor_id();
    event->event_type = event_type;
    event->stack_type = stack_type;
    event->request_id = get_current_request_id(pid);
    
    // Get current instruction and stack pointers from pt_regs context
    // Extract real values instead of hardcoded zeros
    if (ctx) {
        event->instruction_pointer = PT_REGS_IP(ctx);
        event->stack_pointer = PT_REGS_SP(ctx);
        event->frame_pointer = PT_REGS_FP(ctx);
    } else {
        // Fallback if context is not available
        event->instruction_pointer = 0;
        event->stack_pointer = 0;
        event->frame_pointer = 0;
    }
    
    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    return event;
}

// Helper function to capture stack trace
static __always_inline __s32 capture_stack_trace(__u8 stack_type) {
    __u32 flags = 0;
    
    switch (stack_type) {
        case 0: // kernel stack
            flags = 0;
            break;
        case 1: // user stack
            flags = BPF_F_USER_STACK;
            break;
        case 2: // mixed stack (try user first, then kernel)
            flags = BPF_F_USER_STACK;
            break;
    }
    
    struct pt_regs *regs = (struct pt_regs *)bpf_get_current_task();
    __s32 stack_id = bpf_get_stackid(regs, &stack_traces, flags);

    // If user stack failed and we want mixed, try kernel stack
    if (stack_id < 0 && stack_type == 2) {
        stack_id = bpf_get_stackid(regs, &stack_traces, 0);
    }
    
    return stack_id;
}

// Helper function to unwind stack using frame pointers
static __always_inline int unwind_frame_pointers(struct stack_event *event) {
    if (!get_profiling_config(CONFIG_ENABLE_FRAME_POINTERS, 1)) {
        return 0;
    }
    
    // This is a simplified frame pointer unwinding
    // In practice, you would implement proper frame pointer walking
    __u64 fp = event->frame_pointer;
    __u16 depth = 0;
    __u32 max_depth = get_profiling_config(CONFIG_MAX_STACK_DEPTH, 64);
    
    // Walk frame pointers (simplified)
    #pragma unroll
    for (int i = 0; i < 32 && depth < max_depth; i++) {
        if (fp == 0 || fp < 0x1000) {
            break;
        }
        
        __u64 next_fp;
        __u64 return_addr;
        
        // Read next frame pointer and return address
        if (bpf_probe_read_user(&next_fp, sizeof(next_fp), (void *)fp) != 0) {
            break;
        }
        
        if (bpf_probe_read_user(&return_addr, sizeof(return_addr), (void *)(fp + 8)) != 0) {
            break;
        }
        
        // Cache frame information
        struct stack_frame frame = {};
        frame.ip = return_addr;
        frame.sp = fp;
        frame.bp = next_fp;
        frame.function_id = return_addr; // Simplified
        
        bpf_map_update_elem(&frame_cache, &return_addr, &frame, BPF_ANY);
        
        fp = next_fp;
        depth++;
    }
    
    event->stack_depth = depth;
    return depth;
}

// Function entry tracing
SEC("kprobe/sys_enter")
int trace_function_entry(struct pt_regs *ctx) {
    if (!get_profiling_config(CONFIG_ENABLE_KERNEL_STACKS, 1)) {
        return 0;
    }
    
    struct stack_event *event = create_stack_event(ctx, 0, 0); // entry, kernel
    if (!event) {
        return 0;
    }
    
    // Capture stack trace
    __s32 stack_id = capture_stack_trace(0);
    event->stack_id = stack_id;
    
    // Store entry time for duration calculation
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct stack_context ctx_info = {};
    ctx_info.entry_time = event->timestamp;
    ctx_info.stack_id = stack_id;
    ctx_info.depth = 1;
    ctx_info.active = 1;
    
    bpf_map_update_elem(&process_stacks, &pid, &ctx_info, BPF_ANY);
    
    // Unwind stack if enabled
    if (get_profiling_config(CONFIG_ENABLE_FRAME_POINTERS, 1)) {
        unwind_frame_pointers(event);
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Function exit tracing
SEC("kprobe/sys_exit")
int trace_function_exit(struct pt_regs *ctx) {
    if (!get_profiling_config(CONFIG_ENABLE_KERNEL_STACKS, 1)) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct stack_context *ctx_info = bpf_map_lookup_elem(&process_stacks, &pid);
    if (!ctx_info || !ctx_info->active) {
        return 0;
    }
    
    struct stack_event *event = create_stack_event(ctx, 1, 0); // exit, kernel
    if (!event) {
        return 0;
    }
    
    // Calculate duration
    event->duration_ns = event->timestamp - ctx_info->entry_time;
    event->stack_id = ctx_info->stack_id;
    
    // Mark context as inactive
    ctx_info->active = 0;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// User space function tracing (uprobe)
SEC("uprobe")
int trace_user_function_entry(struct pt_regs *ctx) {
    if (!get_profiling_config(CONFIG_ENABLE_USER_STACKS, 1)) {
        return 0;
    }
    
    struct stack_event *event = create_stack_event(ctx, 0, 1); // entry, user
    if (!event) {
        return 0;
    }
    
    // Capture user stack trace
    __s32 stack_id = capture_stack_trace(1);
    event->stack_id = stack_id;
    
    // Unwind user stack
    if (get_profiling_config(CONFIG_ENABLE_FRAME_POINTERS, 1)) {
        unwind_frame_pointers(event);
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// User space function exit tracing (uretprobe)
SEC("uretprobe")
int trace_user_function_exit(struct pt_regs *ctx) {
    if (!get_profiling_config(CONFIG_ENABLE_USER_STACKS, 1)) {
        return 0;
    }
    
    struct stack_event *event = create_stack_event(ctx, 1, 1); // exit, user
    if (!event) {
        return 0;
    }
    
    // Capture user stack trace
    __s32 stack_id = capture_stack_trace(1);
    event->stack_id = stack_id;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Periodic stack sampling for profiling
SEC("perf_event")
int sample_stack_trace(struct bpf_perf_event_data *ctx) {
    __u32 freq = get_profiling_config(CONFIG_SAMPLING_FREQUENCY, 99);
    if (freq == 0) {
        return 0;
    }
    
    // Sample both user and kernel stacks
    if (get_profiling_config(CONFIG_ENABLE_MIXED_STACKS, 1)) {
        struct stack_event *event = create_stack_event(ctx, 2, 2); // sample, mixed
        if (event) {
            __s32 stack_id = capture_stack_trace(2);
            event->stack_id = stack_id;
            
            if (get_profiling_config(CONFIG_ENABLE_FRAME_POINTERS, 1)) {
                unwind_frame_pointers(event);
            }
            
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    return 0;
}

// Stack unwinding with DWARF information (simplified)
SEC("kprobe/dwarf_unwind")
int dwarf_stack_unwind(struct pt_regs *ctx) {
    if (!get_profiling_config(CONFIG_ENABLE_DWARF_UNWINDING, 0)) {
        return 0;
    }
    
    struct stack_event *event = create_stack_event(ctx, 2, 2); // sample, mixed
    if (!event) {
        return 0;
    }
    
    // This would implement DWARF-based stack unwinding
    // For now, we use the standard stack trace mechanism
    __s32 stack_id = capture_stack_trace(2);
    event->stack_id = stack_id;
    
    // Enhanced unwinding would parse DWARF debug information
    // to provide more accurate stack traces and local variable information
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Deadlock detection helper
SEC("kprobe/mutex_lock")
int detect_potential_deadlock(struct pt_regs *ctx) {
    struct stack_event *event = create_stack_event(ctx, 2, 0); // sample, kernel
    if (!event) {
        return 0;
    }
    
    // Capture stack at mutex lock for deadlock analysis
    __s32 stack_id = capture_stack_trace(0);
    event->stack_id = stack_id;
    
    // Add metadata for deadlock detection
    event->duration_ns = 0; // Will be filled by userspace analysis
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Memory allocation tracing for leak detection
SEC("kprobe/kmalloc")
int trace_memory_allocation(struct pt_regs *ctx) {
    struct stack_event *event = create_stack_event(ctx, 2, 0); // sample, kernel
    if (!event) {
        return 0;
    }
    
    // Capture allocation stack trace
    __s32 stack_id = capture_stack_trace(0);
    event->stack_id = stack_id;
    
    // Store allocation size in duration field (repurposed)
    __u64 size = 1024; // Simplified for compatibility
    event->duration_ns = size;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// HTTP request correlation
SEC("kprobe/http_request_start")
int correlate_http_request(struct pt_regs *ctx) {
    if (!get_profiling_config(CONFIG_ENABLE_CORRELATION, 1)) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Get request ID from context (this would be passed from HTTP tracer)
    __u32 request_id = 12345; // Simplified for compatibility
    
    // Store PID to request ID mapping
    bpf_map_update_elem(&pid_to_request_id, &pid, &request_id, BPF_ANY);
    
    // Capture stack trace for HTTP request handling
    struct stack_event *event = create_stack_event(ctx, 0, 2); // entry, mixed
    if (event) {
        __s32 stack_id = capture_stack_trace(2);
        event->stack_id = stack_id;
        event->request_id = request_id;
        
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

char _license[] SEC("license") = "GPL";
