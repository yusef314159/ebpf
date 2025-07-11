#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PAYLOAD_SIZE 256
#define MAX_COMM_SIZE 16
#define MAX_PATH_SIZE 128

// 5-tuple for connection tracking
struct connection_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

// Request context for correlation
struct request_context {
    __u64 request_id;
    __u64 start_time;
    __u32 pid;
    char method[8];
    char path[MAX_PATH_SIZE];
};

// Event structure to pass data to userspace
struct event_t {
    __u64 timestamp;
    __u64 request_id;         // Unique request identifier
    __u32 pid;
    __u32 tid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    char comm[MAX_COMM_SIZE];
    char method[8];           // GET, POST, etc.
    char path[MAX_PATH_SIZE]; // HTTP path
    __u32 payload_len;
    char payload[MAX_PAYLOAD_SIZE];
    __u8 event_type;          // 0=accept, 1=read, 2=connect, 3=write
    __u8 protocol;            // TCP=6, UDP=17
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Map to track socket file descriptors and their connection info
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // file descriptor
    __type(value, struct event_t);
} sock_info SEC(".maps");

// Map to track active requests by PID for correlation
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // PID
    __type(value, struct request_context);
} active_requests SEC(".maps");

// Map to track connections by 5-tuple
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct connection_key);
    __type(value, __u64);  // request_id
} connection_map SEC(".maps");

// Global request ID counter (simple approach for PoC)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} request_id_counter SEC(".maps");

// Helper function to generate unique request ID
static __always_inline __u64 generate_request_id() {
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&request_id_counter, &key);
    if (!counter) {
        __u64 initial_value = 1;
        bpf_map_update_elem(&request_id_counter, &key, &initial_value, BPF_ANY);
        return 1;
    }

    __u64 new_id = *counter + 1;
    bpf_map_update_elem(&request_id_counter, &key, &new_id, BPF_ANY);
    return new_id;
}

// Helper function to extract HTTP method and path from payload
static __always_inline int parse_http_request(char *data, int len, char *method, char *path) {
    if (len < 14) // Minimum for "GET / HTTP/1.1"
        return -1;

    // Extract method (GET, POST, PUT, etc.)
    int method_end = 0;
    for (int i = 0; i < 7 && i < len; i++) {
        if (data[i] == ' ') {
            method_end = i;
            break;
        }
        if (i < 7) method[i] = data[i];
    }
    if (method_end == 0) return -1;
    method[method_end] = '\0';

    // Extract path
    int path_start = method_end + 1;
    int path_end = path_start;
    for (int i = path_start; i < len && i < (path_start + MAX_PATH_SIZE - 1); i++) {
        if (data[i] == ' ' || data[i] == '\r' || data[i] == '\n') {
            path_end = i;
            break;
        }
        path[i - path_start] = data[i];
        path_end = i + 1;
    }
    path[path_end - path_start] = '\0';

    return 0;
}

// Hook into accept() syscall to track new connections
SEC("tracepoint/syscalls/sys_enter_accept")
int trace_accept_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    
    struct event_t *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->request_id = 0; // Will be set when HTTP request is detected
    event->pid = pid;
    event->tid = tid;
    event->event_type = 0; // accept event
    event->protocol = 6;   // TCP

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Initialize other fields
    event->src_ip = 0;
    event->dst_ip = 0;
    event->src_port = 0;
    event->dst_port = 0;
    event->payload_len = 0;
    __builtin_memset(event->method, 0, sizeof(event->method));
    __builtin_memset(event->path, 0, sizeof(event->path));
    __builtin_memset(event->payload, 0, sizeof(event->payload));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Hook into accept() syscall return to get the new socket fd
SEC("tracepoint/syscalls/sys_exit_accept")
int trace_accept_exit(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    if (ret < 0)
        return 0;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ret;
    
    // Store socket info for later use in read()
    struct event_t sock_event = {};
    sock_event.pid = pid;
    sock_event.timestamp = bpf_ktime_get_ns();
    sock_event.request_id = 0; // Will be set when HTTP request is detected
    sock_event.protocol = 6;   // TCP
    bpf_get_current_comm(&sock_event.comm, sizeof(sock_event.comm));

    bpf_map_update_elem(&sock_info, &fd, &sock_event, BPF_ANY);
    return 0;
}

// Hook into read() syscall to capture HTTP requests
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 fd = (__u32)ctx->args[0];
    void *buf = (void *)ctx->args[1];
    size_t count = (size_t)ctx->args[2];
    
    // Check if this fd is a socket we're tracking
    struct event_t *sock_event = bpf_map_lookup_elem(&sock_info, &fd);
    if (!sock_event)
        return 0;
    
    // Only process if buffer size is reasonable
    if (count == 0 || count > MAX_PAYLOAD_SIZE)
        return 0;
    
    struct event_t *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->event_type = 1; // read event
    event->protocol = 6;   // TCP

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Copy socket info
    event->src_ip = sock_event->src_ip;
    event->dst_ip = sock_event->dst_ip;
    event->src_port = sock_event->src_port;
    event->dst_port = sock_event->dst_port;

    // Read payload safely
    int payload_size = count < MAX_PAYLOAD_SIZE ? count : MAX_PAYLOAD_SIZE;
    event->payload_len = payload_size;

    if (bpf_probe_read_user(event->payload, payload_size, buf) == 0) {
        // Try to parse as HTTP request
        if (parse_http_request(event->payload, payload_size, event->method, event->path) == 0) {
            // Successfully parsed HTTP request - generate request ID and store context
            event->request_id = generate_request_id();

            // Store request context for correlation with outbound connections
            struct request_context req_ctx = {};
            req_ctx.request_id = event->request_id;
            req_ctx.start_time = event->timestamp;
            req_ctx.pid = pid;
            __builtin_memcpy(req_ctx.method, event->method, sizeof(req_ctx.method));
            __builtin_memcpy(req_ctx.path, event->path, sizeof(req_ctx.path));

            bpf_map_update_elem(&active_requests, &pid, &req_ctx, BPF_ANY);
        } else {
            // Not an HTTP request, clear method and path
            event->request_id = 0;
            __builtin_memset(event->method, 0, sizeof(event->method));
            __builtin_memset(event->path, 0, sizeof(event->path));
        }
    } else {
        event->request_id = 0;
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Hook into connect() syscall to track outbound connections
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 fd = (__u32)ctx->args[0];

    struct event_t *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->event_type = 2; // connect event
    event->protocol = 6;   // TCP

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Try to correlate with active HTTP request
    struct request_context *req_ctx = bpf_map_lookup_elem(&active_requests, &pid);
    if (req_ctx) {
        event->request_id = req_ctx->request_id;
        __builtin_memcpy(event->method, req_ctx->method, sizeof(event->method));
        __builtin_memcpy(event->path, req_ctx->path, sizeof(event->path));
    } else {
        event->request_id = 0;
        __builtin_memset(event->method, 0, sizeof(event->method));
        __builtin_memset(event->path, 0, sizeof(event->path));
    }

    // Initialize connection fields (would need sockaddr parsing for real IPs)
    event->src_ip = 0;
    event->dst_ip = 0;
    event->src_port = 0;
    event->dst_port = 0;
    event->payload_len = 0;
    __builtin_memset(event->payload, 0, sizeof(event->payload));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
