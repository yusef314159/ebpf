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
#define MAX_METHOD_SIZE 8
#define HTTP_MIN_REQUEST_SIZE 14  // "GET / HTTP/1.1"

// 5-tuple for connection tracking
struct connection_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

// Advanced trace context for distributed tracing
struct trace_context {
    __u64 trace_id_high;      // High 64 bits of 128-bit trace ID
    __u64 trace_id_low;       // Low 64 bits of 128-bit trace ID
    __u64 span_id;            // Current span ID
    __u64 parent_span_id;     // Parent span ID (0 if root)
    __u8 trace_flags;         // Trace flags (sampled, etc.)
    __u8 trace_state_len;     // Length of trace state
    char trace_state[64];     // Trace state for vendor-specific data
};

// Enhanced request context for advanced correlation
struct request_context {
    __u64 request_id;         // Local request ID (backward compatibility)
    __u64 start_time;
    __u32 pid;
    char method[8];
    char path[MAX_PATH_SIZE];

    // Advanced correlation fields
    struct trace_context trace_ctx;
    __u32 service_id;         // Service identifier hash
    __u16 service_port;       // Service port for identification
    __u8 correlation_type;    // 0=local, 1=incoming, 2=outgoing
    __u8 hop_count;           // Number of hops in the trace
};

// Enhanced event structure with distributed tracing support
struct event_t {
    __u64 timestamp;
    __u64 request_id;         // Unique request identifier (backward compatibility)
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

    // Distributed tracing fields
    struct trace_context trace_ctx;
    __u32 service_id;         // Service identifier
    __u8 correlation_type;    // Correlation type
    __u8 hop_count;           // Trace hop count
    __u16 reserved;           // Padding for alignment
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

// Helper function to generate unique request ID with error handling
static __always_inline __u64 generate_request_id() {
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&request_id_counter, &key);
    if (!counter) {
        __u64 initial_value = 1;
        int ret = bpf_map_update_elem(&request_id_counter, &key, &initial_value, BPF_ANY);
        if (ret < 0) {
            // Fallback: use timestamp as request ID if map update fails
            return bpf_ktime_get_ns();
        }
        return 1;
    }

    __u64 new_id = *counter + 1;
    // Check for overflow
    if (new_id == 0) {
        new_id = 1;
    }

    int ret = bpf_map_update_elem(&request_id_counter, &key, &new_id, BPF_ANY);
    if (ret < 0) {
        // Fallback: use timestamp as request ID if map update fails
        return bpf_ktime_get_ns();
    }
    return new_id;
}

// Helper function to generate trace ID (128-bit)
static __always_inline void generate_trace_id(struct trace_context *ctx) {
    if (!ctx) return;

    __u64 timestamp = bpf_ktime_get_ns();
    __u32 pid_tgid = bpf_get_current_pid_tgid();

    // Generate pseudo-random 128-bit trace ID
    ctx->trace_id_high = timestamp;
    ctx->trace_id_low = ((__u64)pid_tgid << 32) | (timestamp & 0xFFFFFFFF);
}

// Helper function to generate span ID
static __always_inline __u64 generate_span_id() {
    __u64 timestamp = bpf_ktime_get_ns();
    __u32 pid_tgid = bpf_get_current_pid_tgid();

    // Generate pseudo-random 64-bit span ID
    return (timestamp ^ ((__u64)pid_tgid << 16));
}

// Helper function to calculate service ID hash from process name and port
static __always_inline __u32 calculate_service_id(const char *comm, __u16 port) {
    __u32 hash = 0;

    // Simple hash function for service identification
    #pragma unroll
    for (int i = 0; i < MAX_COMM_SIZE && i < 16; i++) {
        if (comm[i] == 0) break;
        hash = hash * 31 + comm[i];
    }

    // Include port in hash
    hash = hash * 31 + port;

    return hash;
}

// Helper function to extract trace context from HTTP headers
static __always_inline int extract_trace_context_from_headers(const char *payload, int len, struct trace_context *ctx) {
    if (!payload || !ctx || len < 20) {
        return -1;
    }

    // Look for common tracing headers
    // X-Trace-Id, traceparent, X-B3-TraceId, etc.

    // Simple implementation: look for "traceparent:" header (W3C standard)
    #pragma unroll
    for (int i = 0; i < len - 12 && i < MAX_PAYLOAD_SIZE - 12; i++) {
        if (__builtin_memcmp(&payload[i], "traceparent:", 12) == 0) {
            // Found traceparent header, extract trace context
            // Format: 00-<trace_id>-<span_id>-<flags>
            // This is a simplified extraction - full implementation would parse the header

            // For now, mark that we found a trace context
            ctx->trace_flags = 1; // Mark as having external trace context
            return 0;
        }
    }

    // Also check for X-Trace-Id header (common in many systems)
    #pragma unroll
    for (int i = 0; i < len - 10 && i < MAX_PAYLOAD_SIZE - 10; i++) {
        if (__builtin_memcmp(&payload[i], "X-Trace-Id:", 11) == 0) {
            ctx->trace_flags = 2; // Mark as having X-Trace-Id
            return 0;
        }
    }

    return -1; // No trace context found
}

// Helper function to initialize trace context for new request
static __always_inline void init_trace_context(struct trace_context *ctx, __u8 correlation_type) {
    if (!ctx) return;

    __builtin_memset(ctx, 0, sizeof(*ctx));

    if (correlation_type == 0) { // New root trace
        generate_trace_id(ctx);
        ctx->span_id = generate_span_id();
        ctx->parent_span_id = 0;
        ctx->trace_flags = 1; // Sampled
    }
    // For incoming requests (correlation_type == 1), trace context should be extracted from headers
    // For outgoing requests (correlation_type == 2), trace context should be inherited from parent
}

// Helper function to validate HTTP method
static __always_inline int is_valid_http_method(const char *method, int len) {
    if (len < 3 || len > 7) {
        return 0;
    }

    // Check common HTTP methods
    if (len == 3) {
        return (__builtin_memcmp(method, "GET", 3) == 0 ||
                __builtin_memcmp(method, "PUT", 3) == 0);
    } else if (len == 4) {
        return (__builtin_memcmp(method, "POST", 4) == 0 ||
                __builtin_memcmp(method, "HEAD", 4) == 0);
    } else if (len == 5) {
        return (__builtin_memcmp(method, "PATCH", 5) == 0 ||
                __builtin_memcmp(method, "TRACE", 5) == 0);
    } else if (len == 6) {
        return (__builtin_memcmp(method, "DELETE", 6) == 0);
    } else if (len == 7) {
        return (__builtin_memcmp(method, "OPTIONS", 7) == 0 ||
                __builtin_memcmp(method, "CONNECT", 7) == 0);
    }

    return 0;
}

// Helper function to check if data looks like HTTP request
static __always_inline int is_http_request_start(const char *data, int len) {
    if (len < HTTP_MIN_REQUEST_SIZE) {
        return 0;
    }

    // Look for HTTP version at the end
    for (int i = HTTP_MIN_REQUEST_SIZE; i < len - 8; i++) {
        if (data[i] == 'H' && data[i+1] == 'T' && data[i+2] == 'T' && data[i+3] == 'P' && data[i+4] == '/') {
            // Found HTTP/ - check version
            if ((data[i+5] == '1' && data[i+6] == '.' && (data[i+7] == '0' || data[i+7] == '1')) ||
                (data[i+5] == '2' && data[i+6] == '.' && data[i+7] == '0')) {
                return 1;
            }
        }
    }

    return 0;
}

// Enhanced HTTP request parser with comprehensive validation
static __always_inline int parse_http_request(char *data, int len, char *method, char *path) {
    // Validate input parameters
    if (!data || !method || !path || len < HTTP_MIN_REQUEST_SIZE) {
        return -1;
    }

    // Initialize output buffers
    __builtin_memset(method, 0, MAX_METHOD_SIZE);
    __builtin_memset(path, 0, MAX_PATH_SIZE);

    // Quick check if this looks like an HTTP request
    if (!is_http_request_start(data, len)) {
        return -1;
    }

    // Extract method (GET, POST, PUT, etc.) with bounds checking
    int method_end = 0;
    int method_len = 0;

    #pragma unroll
    for (int i = 0; i < (MAX_METHOD_SIZE - 1) && i < len; i++) {
        char c = data[i];

        // Check for non-printable characters or control characters
        if (c < 32 || c > 126) {
            return -1;
        }

        if (c == ' ') {
            method_end = i;
            break;
        }

        // Only copy uppercase letters for HTTP methods
        if (method_len < (MAX_METHOD_SIZE - 1) && c >= 'A' && c <= 'Z') {
            method[method_len] = c;
            method_len++;
        } else if (c >= 'a' && c <= 'z') {
            // Convert lowercase to uppercase
            method[method_len] = c - 32;
            method_len++;
        } else {
            // Invalid character in method
            return -1;
        }
    }

    // Validate method was found and is a known HTTP method
    if (method_end == 0 || !is_valid_http_method(method, method_len)) {
        return -1;
    }

    // Extract path with enhanced bounds checking
    int path_start = method_end + 1;
    int path_len = 0;

    // Ensure we don't go beyond buffer
    if (path_start >= len) {
        return -1;
    }

    // Find the end of the path (space before HTTP version)
    int path_end = path_start;
    #pragma unroll
    for (int i = path_start; i < len && path_len < (MAX_PATH_SIZE - 1); i++) {
        char c = data[i];

        // End of path markers
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t') {
            path_end = i;
            break;
        }

        // Validate path characters (allow more characters for URLs)
        if (c < 32 || c > 126) {
            return -1;
        }

        // Common URL characters validation
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '/' || c == '.' ||
            c == '-' || c == '_' || c == '?' || c == '&' ||
            c == '=' || c == '%' || c == ':' || c == '@' ||
            c == '!' || c == '*' || c == '\'' || c == '(' ||
            c == ')' || c == ';' || c == '+' || c == '$' ||
            c == ',' || c == '[' || c == ']') {
            path[path_len] = c;
            path_len++;
        } else {
            // Invalid character in path
            return -1;
        }
    }

    // Validate path was found and starts with '/'
    if (path_len == 0 || path[0] != '/') {
        return -1;
    }

    // Additional validation: check if HTTP version follows the path
    if (path_end < len - 8) {
        int version_start = path_end + 1;
        if (version_start < len - 8 &&
            data[version_start] == 'H' && data[version_start + 1] == 'T' &&
            data[version_start + 2] == 'T' && data[version_start + 3] == 'P') {
            // Valid HTTP request structure
            return 0;
        }
    }

    return -1;
}

// Hook into accept() syscall to track new connections with enhanced error handling
SEC("tracepoint/syscalls/sys_enter_accept")
int trace_accept_enter(struct trace_event_raw_sys_enter *ctx) {
    // Validate context pointer
    if (!ctx) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    // Skip kernel threads (PID 0) and invalid PIDs
    if (pid == 0 || pid > 0x7FFFFFFF) {
        return 0;
    }

    struct event_t *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) {
        // Ring buffer is full, drop event gracefully
        return 0;
    }

    // Initialize all fields to prevent information leakage
    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp = bpf_ktime_get_ns();
    event->request_id = 0; // Will be set when HTTP request is detected
    event->pid = pid;
    event->tid = tid;
    event->event_type = 0; // accept event
    event->protocol = 6;   // TCP

    // Safely get current command name
    int ret = bpf_get_current_comm(&event->comm, sizeof(event->comm));
    if (ret < 0) {
        // If we can't get comm, use a placeholder
        __builtin_memcpy(event->comm, "unknown", 8);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Hook into accept() syscall return to get the new socket fd with enhanced error handling
SEC("tracepoint/syscalls/sys_exit_accept")
int trace_accept_exit(struct trace_event_raw_sys_exit *ctx) {
    // Validate context pointer
    if (!ctx) {
        return 0;
    }

    long ret = ctx->ret;
    // Check for accept() failure or invalid file descriptor
    if (ret < 0 || ret > 0x7FFFFFFF) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ret;

    // Skip kernel threads and invalid PIDs
    if (pid == 0 || pid > 0x7FFFFFFF) {
        return 0;
    }

    // Store socket info for later use in read()
    struct event_t sock_event = {};
    __builtin_memset(&sock_event, 0, sizeof(sock_event));

    sock_event.pid = pid;
    sock_event.timestamp = bpf_ktime_get_ns();
    sock_event.request_id = 0; // Will be set when HTTP request is detected
    sock_event.protocol = 6;   // TCP

    // Safely get current command name
    int comm_ret = bpf_get_current_comm(&sock_event.comm, sizeof(sock_event.comm));
    if (comm_ret < 0) {
        __builtin_memcpy(sock_event.comm, "unknown", 8);
    }

    // Update socket info map with error checking
    int map_ret = bpf_map_update_elem(&sock_info, &fd, &sock_event, BPF_ANY);
    if (map_ret < 0) {
        // Map update failed, but we continue gracefully
        // In production, we might want to increment an error counter here
    }

    return 0;
}

// Hook into read() syscall to capture HTTP requests with enhanced error handling
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
    // Validate context pointer
    if (!ctx) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    // Skip kernel threads and invalid PIDs
    if (pid == 0 || pid > 0x7FFFFFFF) {
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    void *buf = (void *)ctx->args[1];
    size_t count = (size_t)ctx->args[2];

    // Validate file descriptor range
    if (fd > 0x7FFFFFFF) {
        return 0;
    }

    // Validate buffer pointer (basic check)
    if (!buf) {
        return 0;
    }

    // Check if this fd is a socket we're tracking
    struct event_t *sock_event = bpf_map_lookup_elem(&sock_info, &fd);
    if (!sock_event) {
        return 0;
    }

    // Only process if buffer size is reasonable (avoid excessive memory reads)
    if (count == 0 || count > MAX_PAYLOAD_SIZE || count > 0x10000) {
        return 0;
    }

    struct event_t *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) {
        // Ring buffer full, drop event gracefully
        return 0;
    }

    // Initialize all fields to prevent information leakage
    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->event_type = 1; // read event
    event->protocol = 6;   // TCP

    // Safely get current command name
    int comm_ret = bpf_get_current_comm(&event->comm, sizeof(event->comm));
    if (comm_ret < 0) {
        __builtin_memcpy(event->comm, "unknown", 8);
    }

    // Copy socket info safely
    event->src_ip = sock_event->src_ip;
    event->dst_ip = sock_event->dst_ip;
    event->src_port = sock_event->src_port;
    event->dst_port = sock_event->dst_port;

    // Read payload safely with bounds checking
    int payload_size = count < MAX_PAYLOAD_SIZE ? count : MAX_PAYLOAD_SIZE;
    event->payload_len = payload_size;

    // Attempt to read user data with error handling
    int read_ret = bpf_probe_read_user(event->payload, payload_size, buf);
    if (read_ret == 0) {
        // Try to parse as HTTP request
        int parse_ret = parse_http_request(event->payload, payload_size, event->method, event->path);
        if (parse_ret == 0) {
            // Successfully parsed HTTP request - generate request ID and store context
            event->request_id = generate_request_id();

            // Initialize distributed tracing context
            init_trace_context(&event->trace_ctx, 1); // Incoming request

            // Try to extract trace context from HTTP headers
            int trace_extracted = extract_trace_context_from_headers(event->payload, payload_size, &event->trace_ctx);
            if (trace_extracted != 0) {
                // No existing trace context found, create new root trace
                init_trace_context(&event->trace_ctx, 0); // New root trace
                event->correlation_type = 0; // Local/root
                event->hop_count = 0;
            } else {
                // Found existing trace context, this is part of distributed trace
                event->correlation_type = 1; // Incoming
                event->hop_count = 1; // At least one hop
            }

            // Calculate service ID
            event->service_id = calculate_service_id(event->comm, event->dst_port);

            // Store enhanced request context for correlation
            struct request_context req_ctx = {};
            __builtin_memset(&req_ctx, 0, sizeof(req_ctx));

            req_ctx.request_id = event->request_id;
            req_ctx.start_time = event->timestamp;
            req_ctx.pid = pid;
            __builtin_memcpy(req_ctx.method, event->method, sizeof(req_ctx.method));
            __builtin_memcpy(req_ctx.path, event->path, sizeof(req_ctx.path));

            // Copy trace context
            __builtin_memcpy(&req_ctx.trace_ctx, &event->trace_ctx, sizeof(req_ctx.trace_ctx));
            req_ctx.service_id = event->service_id;
            req_ctx.service_port = event->dst_port;
            req_ctx.correlation_type = event->correlation_type;
            req_ctx.hop_count = event->hop_count;

            // Update active requests map with error handling
            int map_ret = bpf_map_update_elem(&active_requests, &pid, &req_ctx, BPF_ANY);
            if (map_ret < 0) {
                // Map update failed, but we continue with the event
                // In production, we might want to increment an error counter
            }
        } else {
            // Not an HTTP request, clear method and path
            event->request_id = 0;
        }
    } else {
        // Failed to read user data
        event->request_id = 0;
        event->payload_len = 0;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Hook into connect() syscall to track outbound connections with enhanced error handling
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx) {
    // Validate context pointer
    if (!ctx) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 fd = (__u32)ctx->args[0];

    // Skip kernel threads and invalid PIDs
    if (pid == 0 || pid > 0x7FFFFFFF) {
        return 0;
    }

    // Validate file descriptor range
    if (fd > 0x7FFFFFFF) {
        return 0;
    }

    struct event_t *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) {
        // Ring buffer full, drop event gracefully
        return 0;
    }

    // Initialize all fields to prevent information leakage
    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->event_type = 2; // connect event
    event->protocol = 6;   // TCP

    // Safely get current command name
    int comm_ret = bpf_get_current_comm(&event->comm, sizeof(event->comm));
    if (comm_ret < 0) {
        __builtin_memcpy(event->comm, "unknown", 8);
    }

    // Try to correlate with active HTTP request
    struct request_context *req_ctx = bpf_map_lookup_elem(&active_requests, &pid);
    if (req_ctx) {
        event->request_id = req_ctx->request_id;
        __builtin_memcpy(event->method, req_ctx->method, sizeof(event->method));
        __builtin_memcpy(event->path, req_ctx->path, sizeof(event->path));
    }
    // Note: Fields are already zeroed by memset above, so no need for explicit else clause

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Helper function to parse HTTP response
static __always_inline int parse_http_response(const char *data, int len, char *status_code, char *reason_phrase) {
    if (len < 12) { // "HTTP/1.1 200" minimum
        return -1;
    }

    // Check for HTTP response format
    if (__builtin_memcmp(data, "HTTP/", 5) != 0) {
        return -1;
    }

    // Find the status code (after "HTTP/1.x ")
    int space_count = 0;
    int status_start = -1;

    #pragma unroll
    for (int i = 0; i < len && i < 20; i++) {
        if (data[i] == ' ') {
            space_count++;
            if (space_count == 1) {
                status_start = i + 1;
                break;
            }
        }
    }

    if (status_start == -1 || status_start + 3 > len) {
        return -1;
    }

    // Extract status code (3 digits)
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        if (status_start + i < len) {
            status_code[i] = data[status_start + i];
        }
    }
    status_code[3] = '\0';

    // Extract reason phrase (optional)
    int reason_start = status_start + 4; // Skip "200 "
    if (reason_start < len) {
        int reason_len = 0;
        #pragma unroll
        for (int i = reason_start; i < len && i < reason_start + 32 && reason_len < 31; i++) {
            if (data[i] == '\r' || data[i] == '\n') {
                break;
            }
            reason_phrase[reason_len++] = data[i];
        }
        reason_phrase[reason_len] = '\0';
    }

    return 0;
}

// Hook into write() syscall to capture HTTP responses
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx) {
    // Validate context pointer
    if (!ctx) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 fd = (__u32)ctx->args[0];
    const char __user *buf = (const char __user *)ctx->args[1];
    size_t count = (size_t)ctx->args[2];

    // Skip kernel threads and invalid PIDs
    if (pid == 0 || pid > 0x7FFFFFFF) {
        return 0;
    }

    // Validate file descriptor range
    if (fd > 0x7FFFFFFF) {
        return 0;
    }

    // Validate buffer pointer
    if (!buf) {
        return 0;
    }

    // Check if this fd is a socket we're tracking
    struct event_t *sock_event = bpf_map_lookup_elem(&sock_info, &fd);
    if (!sock_event) {
        return 0;
    }

    // Only process if buffer size is reasonable
    if (count == 0 || count > MAX_PAYLOAD_SIZE || count > 0x10000) {
        return 0;
    }

    struct event_t *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event) {
        // Ring buffer full, drop event gracefully
        return 0;
    }

    // Initialize all fields to prevent information leakage
    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->event_type = 3; // write event
    event->protocol = 6;   // TCP

    // Safely get current command name
    int comm_ret = bpf_get_current_comm(&event->comm, sizeof(event->comm));
    if (comm_ret < 0) {
        __builtin_memcpy(event->comm, "unknown", 8);
    }

    // Copy socket info safely
    event->src_ip = sock_event->src_ip;
    event->dst_ip = sock_event->dst_ip;
    event->src_port = sock_event->src_port;
    event->dst_port = sock_event->dst_port;

    // Read payload safely with bounds checking
    int payload_size = count < MAX_PAYLOAD_SIZE ? count : MAX_PAYLOAD_SIZE;
    event->payload_len = payload_size;

    // Attempt to read user data with error handling
    int read_ret = bpf_probe_read_user(event->payload, payload_size, buf);
    if (read_ret == 0) {
        // Try to parse as HTTP response
        char status_code[4] = {0};
        char reason_phrase[32] = {0};

        int parse_ret = parse_http_response(event->payload, payload_size, status_code, reason_phrase);
        if (parse_ret == 0) {
            // Successfully parsed HTTP response - try to correlate with request
            struct request_context *req_ctx = bpf_map_lookup_elem(&active_requests, &pid);
            if (req_ctx) {
                event->request_id = req_ctx->request_id;
                __builtin_memcpy(event->method, req_ctx->method, sizeof(event->method));
                __builtin_memcpy(event->path, req_ctx->path, sizeof(event->path));

                // Store status code in unused part of method field for responses
                __builtin_memcpy(event->method, status_code, 4);
            } else {
                // No matching request context, generate new ID
                event->request_id = generate_request_id();
                __builtin_memcpy(event->method, status_code, 4);
            }
        } else {
            // Not an HTTP response, but still track the write
            struct request_context *req_ctx = bpf_map_lookup_elem(&active_requests, &pid);
            if (req_ctx) {
                event->request_id = req_ctx->request_id;
                __builtin_memcpy(event->method, req_ctx->method, sizeof(event->method));
                __builtin_memcpy(event->path, req_ctx->path, sizeof(event->path));
            }
        }
    } else {
        // Failed to read user data
        event->request_id = 0;
        event->payload_len = 0;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
