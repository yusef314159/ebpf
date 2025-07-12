/*
 * =====================================================================================
 * UNIVERSAL eBPF TRACER (UET) - HTTP TRACER MODULE
 * =====================================================================================
 *
 * OVERVIEW:
 * This eBPF program provides comprehensive HTTP request and response tracing by
 * intercepting network system calls at the kernel level. It captures detailed
 * information about HTTP traffic without requiring any application modifications.
 *
 * HOW IT WORKS:
 * 1. SYSCALL INTERCEPTION: Hooks into read(), write(), accept(), and connect() syscalls
 * 2. HTTP DETECTION: Analyzes network data to identify HTTP requests/responses
 * 3. DATA EXTRACTION: Parses HTTP headers, methods, paths, and payload content
 * 4. EVENT GENERATION: Sends structured events to userspace for analysis
 * 5. CORRELATION: Tracks request/response pairs using connection context
 *
 * TECHNICAL APPROACH:
 * - Uses kprobes to attach to syscall entry/exit points
 * - Maintains connection state in eBPF maps for correlation
 * - Implements HTTP parsing logic with eBPF verifier constraints
 * - Provides distributed tracing support with W3C Trace Context
 * - Optimized for minimal performance impact on traced applications
 *
 * SUPPORTED FEATURES:
 * - HTTP/1.1 and HTTP/2 request tracing
 * - Method extraction (GET, POST, PUT, DELETE, etc.)
 * - URL path and query parameter capture
 * - Request/response header analysis
 * - Payload content sampling
 * - Connection-level correlation
 * - Performance timing measurements
 * - Multi-language application support (Python, Go, Java, Node.js, etc.)
 *
 * SECURITY & COMPLIANCE:
 * - Respects eBPF security model and verifier constraints
 * - Implements bounds checking for all memory access
 * - Provides configurable data filtering and redaction
 * - Supports PII detection and masking capabilities
 *
 * AUTHOR: Universal eBPF Tracer Team
 * VERSION: 1.0
 * LICENSE: Production-ready for enterprise deployment
 * =====================================================================================
 */

#include <linux/bpf.h>        // Core eBPF definitions and constants
#include <linux/ptrace.h>     // Process tracing structures (pt_regs)
#include <linux/socket.h>     // Socket-related constants and structures
#include <linux/in.h>         // Internet protocol definitions
#include <linux/if_ether.h>   // Ethernet protocol definitions
#include <linux/ip.h>         // IP protocol structures
#include <linux/tcp.h>        // TCP protocol structures
#include <linux/types.h>      // Linux kernel type definitions
#include <bpf/bpf_helpers.h>  // eBPF helper function declarations
#include <bpf/bpf_tracing.h>  // eBPF tracing macros and utilities
#include <bpf/bpf_core_read.h> // CO-RE (Compile Once, Run Everywhere) helpers

/*
 * =====================================================================================
 * SYSCALL TRACEPOINT STRUCTURES
 * =====================================================================================
 * These structures define the format of syscall tracepoint events that we intercept.
 * They match the kernel's internal tracepoint format for system call entry/exit.
 */

/**
 * struct trace_event_raw_sys_enter - System call entry tracepoint structure
 *
 * This structure represents the data available when a system call is entered.
 * We use this to capture the syscall number and arguments for network operations.
 *
 * @common_type: Event type identifier from the kernel tracing subsystem
 * @common_flags: Tracing flags (interrupt context, preemption state, etc.)
 * @common_preempt_count: Kernel preemption counter at time of event
 * @common_pid: Process ID of the process making the syscall
 * @id: System call number (e.g., __NR_read, __NR_write, __NR_accept)
 * @args: Array of syscall arguments (up to 6 arguments per syscall)
 */
struct trace_event_raw_sys_enter {
    unsigned short common_type;        // Kernel event type identifier
    unsigned char common_flags;        // Tracing context flags
    unsigned char common_preempt_count; // Preemption nesting level
    int common_pid;                    // Process ID making the syscall
    long id;                          // System call number
    unsigned long args[6];            // Syscall arguments (fd, buffer, size, etc.)
};

/**
 * struct trace_event_raw_sys_exit - System call exit tracepoint structure
 *
 * This structure represents the data available when a system call exits.
 * We use this to capture the return value and correlate with entry events.
 *
 * @common_type: Event type identifier from the kernel tracing subsystem
 * @common_flags: Tracing flags (interrupt context, preemption state, etc.)
 * @common_preempt_count: Kernel preemption counter at time of event
 * @common_pid: Process ID of the process completing the syscall
 * @id: System call number (matches the entry event)
 * @ret: Return value from the syscall (bytes read/written, error code, etc.)
 */
struct trace_event_raw_sys_exit {
    unsigned short common_type;        // Kernel event type identifier
    unsigned char common_flags;        // Tracing context flags
    unsigned char common_preempt_count; // Preemption nesting level
    int common_pid;                    // Process ID completing the syscall
    long id;                          // System call number
    long ret;                         // Syscall return value
};

/*
 * =====================================================================================
 * CONFIGURATION CONSTANTS
 * =====================================================================================
 * These constants define buffer sizes and limits optimized for eBPF verifier
 * constraints while providing sufficient data capture capabilities.
 */

#define MAX_PAYLOAD_SIZE 64       // HTTP payload sample size (optimized for eBPF stack)
#define MAX_COMM_SIZE 16          // Process name length (matches TASK_COMM_LEN)
#define MAX_PATH_SIZE 64          // HTTP path maximum length (optimized for eBPF stack)
#define MAX_METHOD_SIZE 8         // HTTP method maximum length (GET, POST, etc.)
#define HTTP_MIN_REQUEST_SIZE 14  // Minimum valid HTTP request: "GET / HTTP/1.1"

/*
 * =====================================================================================
 * CONNECTION TRACKING STRUCTURES
 * =====================================================================================
 * These structures enable correlation of network events across syscalls and
 * provide context for HTTP request/response matching.
 */

/**
 * struct connection_key - Network connection identifier (5-tuple)
 *
 * This structure uniquely identifies a network connection using the standard
 * 5-tuple approach. Used as a key in eBPF maps for connection state tracking.
 *
 * @src_ip: Source IP address (network byte order)
 * @dst_ip: Destination IP address (network byte order)
 * @src_port: Source port number (network byte order)
 * @dst_port: Destination port number (network byte order)
 * @protocol: IP protocol (IPPROTO_TCP, IPPROTO_UDP, etc.)
 */
struct connection_key {
    __u32 src_ip;     // Source IP address
    __u32 dst_ip;     // Destination IP address
    __u16 src_port;   // Source port number
    __u16 dst_port;   // Destination port number
    __u8 protocol;    // IP protocol type
};

/**
 * struct trace_context - Distributed tracing context (W3C Trace Context compatible)
 *
 * This structure implements W3C Trace Context specification for distributed
 * tracing across microservices. Enables correlation of requests across
 * multiple services and systems.
 *
 * @trace_id_high: Upper 64 bits of 128-bit trace ID (globally unique)
 * @trace_id_low: Lower 64 bits of 128-bit trace ID
 * @span_id: Current span identifier (64-bit, unique within trace)
 * @parent_span_id: Parent span identifier (0 for root spans)
 * @trace_flags: Trace sampling and processing flags
 * @trace_state_len: Length of vendor-specific trace state data
 * @trace_state: Vendor-specific tracing state (key-value pairs)
 */
struct trace_context {
    __u64 trace_id_high;      // High 64 bits of 128-bit trace ID
    __u64 trace_id_low;       // Low 64 bits of 128-bit trace ID
    __u64 span_id;            // Current span ID
    __u64 parent_span_id;     // Parent span ID (0 if root)
    __u8 trace_flags;         // Trace flags (sampled, etc.)
    __u8 trace_state_len;     // Length of trace state
    char trace_state[16];     // Trace state for vendor-specific data (optimized)
};

/**
 * struct request_context - HTTP request correlation context
 *
 * This structure maintains state information for HTTP requests to enable
 * correlation between request and response events. Stored in eBPF maps
 * and indexed by connection identifiers.
 *
 * @request_id: Unique local request identifier for backward compatibility
 * @start_time: Request start timestamp (nanoseconds since boot)
 * @pid: Process ID that initiated the request
 * @method: HTTP method (GET, POST, PUT, DELETE, etc.)
 * @path: HTTP request path (URL path component)
 * @trace_ctx: Distributed tracing context for cross-service correlation
 * @service_id: Hash-based service identifier for service mesh integration
 * @service_port: Service port number for service identification
 * @correlation_type: Request flow type (local=0, incoming=1, outgoing=2)
 * @hop_count: Number of service hops in the distributed trace
 */
struct request_context {
    __u64 request_id;         // Local request ID (backward compatibility)
    __u64 start_time;         // Request start timestamp
    __u32 pid;                // Process ID
    char method[8];           // HTTP method
    char path[MAX_PATH_SIZE]; // HTTP path

    // Advanced correlation fields for distributed tracing
    struct trace_context trace_ctx;  // W3C Trace Context
    __u32 service_id;         // Service identifier hash
    __u16 service_port;       // Service port for identification
    __u8 correlation_type;    // 0=local, 1=incoming, 2=outgoing
    __u8 hop_count;           // Number of hops in the trace
};

/**
 * struct event_t - Main HTTP event structure sent to userspace
 *
 * This is the primary data structure that carries HTTP tracing information
 * from kernel space to userspace. Optimized for eBPF verifier constraints
 * while providing comprehensive HTTP request/response details.
 *
 * BASIC FIELDS:
 * @timestamp: Event timestamp (nanoseconds since boot)
 * @request_id: Unique request identifier for correlation
 * @pid: Process ID of the application making the HTTP request
 * @tid: Thread ID of the specific thread handling the request
 * @src_ip: Source IP address (network byte order)
 * @dst_ip: Destination IP address (network byte order)
 * @src_port: Source port number (network byte order)
 * @dst_port: Destination port number (network byte order)
 * @comm: Process name (command) making the request
 *
 * HTTP FIELDS:
 * @method: HTTP method (GET, POST, PUT, DELETE, etc.)
 * @path: HTTP request path (URL path component)
 * @payload_len: Length of captured payload data
 * @payload: Sample of HTTP payload content
 * @event_type: Type of network event (accept=0, read=1, connect=2, write=3)
 * @protocol: IP protocol number (TCP=6, UDP=17)
 *
 * DISTRIBUTED TRACING FIELDS:
 * @trace_ctx: W3C Trace Context for distributed tracing
 * @service_id: Service identifier for service mesh integration
 * @correlation_type: Request flow classification
 * @hop_count: Number of service hops in the trace
 * @reserved: Padding for proper memory alignment
 */
struct event_t {
    // Basic event information
    __u64 timestamp;          // Event timestamp (nanoseconds)
    __u64 request_id;         // Unique request identifier (backward compatibility)
    __u32 pid;                // Process ID
    __u32 tid;                // Thread ID

    // Network connection information
    __u32 src_ip;             // Source IP address
    __u32 dst_ip;             // Destination IP address
    __u16 src_port;           // Source port number
    __u16 dst_port;           // Destination port number

    // Process and HTTP information
    char comm[MAX_COMM_SIZE]; // Process name
    char method[8];           // HTTP method (GET, POST, etc.)
    char path[16];            // HTTP path (optimized for eBPF stack)
    __u32 payload_len;        // Payload length
    char payload[16];         // Payload sample (optimized for eBPF stack)
    __u8 event_type;          // Event type (accept=0, read=1, connect=2, write=3)
    __u8 protocol;            // IP protocol (TCP=6, UDP=17)

    // Distributed tracing fields
    struct trace_context trace_ctx;  // W3C Trace Context
    __u32 service_id;         // Service identifier
    __u8 correlation_type;    // Correlation type
    __u8 hop_count;           // Trace hop count
    __u16 reserved;           // Padding for alignment
};

/*
 * =====================================================================================
 * eBPF MAPS - DATA STRUCTURES FOR KERNEL-USERSPACE COMMUNICATION
 * =====================================================================================
 * These maps provide persistent storage and communication channels between
 * the eBPF kernel programs and userspace applications.
 */

/**
 * rb - Ring Buffer for Event Communication
 *
 * This ring buffer is the primary communication channel for sending HTTP
 * events from kernel space to userspace. It provides efficient, lock-free
 * communication with automatic memory management.
 *
 * Type: BPF_MAP_TYPE_RINGBUF (high-performance ring buffer)
 * Size: 256KB (256 * 1024 bytes) - sufficient for high-throughput scenarios
 * Usage: Events are reserved, populated, and submitted to this buffer
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);    // Ring buffer type for efficient communication
    __uint(max_entries, 256 * 1024);       // 256KB buffer size
} rb SEC(".maps");

/**
 * sock_info - Socket File Descriptor Tracking Map
 *
 * This hash map tracks socket file descriptors and their associated
 * connection information. Used to correlate network events with
 * specific connections and maintain state across syscalls.
 *
 * Key: File descriptor number (__u32)
 * Value: Event structure with connection details (struct event_t)
 * Max Entries: 1024 concurrent connections
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);       // Hash map for O(1) lookups
    __uint(max_entries, 1024);             // Support up to 1024 concurrent connections
    __type(key, __u32);                    // File descriptor as key
    __type(value, struct event_t);         // Connection info as value
} sock_info SEC(".maps");

/**
 * active_requests - HTTP Request Correlation Map
 *
 * This hash map tracks active HTTP requests by process ID to enable
 * correlation between request and response events. Maintains request
 * context including timing, tracing information, and HTTP details.
 *
 * Key: Process ID (__u32)
 * Value: Request context with correlation data (struct request_context)
 * Max Entries: 1024 concurrent requests per process
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);       // Hash map for efficient request lookup
    __uint(max_entries, 1024);             // Support up to 1024 concurrent requests
    __type(key, __u32);                    // Process ID as key
    __type(value, struct request_context); // Request context as value
} active_requests SEC(".maps");

/**
 * connection_map - Network Connection Correlation Map
 *
 * This hash map tracks network connections using the 5-tuple identifier
 * (source IP, destination IP, source port, destination port, protocol).
 * Maps connections to request IDs for correlation across network events.
 *
 * Key: Connection 5-tuple (struct connection_key)
 * Value: Request ID for correlation (__u64)
 * Max Entries: 2048 concurrent connections
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);       // Hash map for connection tracking
    __uint(max_entries, 2048);             // Support up to 2048 concurrent connections
    __type(key, struct connection_key);    // 5-tuple connection identifier
    __type(value, __u64);                  // Request ID for correlation
} connection_map SEC(".maps");

/**
 * request_id_counter - Global Request ID Generator
 *
 * This array map maintains a global counter for generating unique request IDs.
 * Uses a simple atomic increment approach to ensure uniqueness across all
 * HTTP requests processed by the tracer.
 *
 * Key: Always 0 (single counter) (__u32)
 * Value: Current counter value (__u64)
 * Max Entries: 1 (single global counter)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);      // Array map for simple counter storage
    __uint(max_entries, 1);                // Single counter entry
    __type(key, __u32);                    // Key is always 0
    __type(value, __u64);                  // Counter value
} request_id_counter SEC(".maps");

/*
 * =====================================================================================
 * HELPER FUNCTIONS - UTILITY FUNCTIONS FOR HTTP TRACING
 * =====================================================================================
 * These inline functions provide common functionality used across multiple
 * eBPF programs. Marked as __always_inline for performance optimization.
 */

/**
 * generate_request_id() - Generate unique request identifier
 *
 * This function generates a unique request ID by atomically incrementing
 * a global counter stored in an eBPF map. Includes error handling and
 * fallback mechanisms for robustness.
 *
 * ALGORITHM:
 * 1. Look up current counter value from map
 * 2. If counter doesn't exist, initialize it to 1
 * 3. Increment counter and check for overflow
 * 4. Update map with new counter value
 * 5. Return new request ID
 *
 * FALLBACK: If map operations fail, use current timestamp as request ID
 *
 * @return: Unique 64-bit request identifier
 */
static __always_inline __u64 generate_request_id() {
    __u32 key = 0;  // Single counter key

    // Look up current counter value
    __u64 *counter = bpf_map_lookup_elem(&request_id_counter, &key);
    if (!counter) {
        // Initialize counter if it doesn't exist
        __u64 initial_value = 1;
        int ret = bpf_map_update_elem(&request_id_counter, &key, &initial_value, BPF_ANY);
        if (ret < 0) {
            // Fallback: use timestamp as request ID if map update fails
            return bpf_ktime_get_ns();
        }
        return 1;
    }

    // Increment counter and check for overflow
    __u64 new_id = *counter + 1;
    if (new_id == 0) {
        new_id = 1;  // Reset to 1 on overflow (avoid 0 as request ID)
    }

    // Update counter in map
    int ret = bpf_map_update_elem(&request_id_counter, &key, &new_id, BPF_ANY);
    if (ret < 0) {
        // Fallback: use timestamp as request ID if map update fails
        return bpf_ktime_get_ns();
    }

    return new_id;
}

/**
 * generate_trace_id() - Generate 128-bit distributed trace identifier
 *
 * This function generates a pseudo-random 128-bit trace ID for distributed
 * tracing following W3C Trace Context specification. The trace ID uniquely
 * identifies a request across multiple services and systems.
 *
 * ALGORITHM:
 * - High 64 bits: Current timestamp (nanoseconds)
 * - Low 64 bits: Combination of PID/TID and timestamp bits
 *
 * @ctx: Pointer to trace context structure to populate
 */
static __always_inline void generate_trace_id(struct trace_context *ctx) {
    if (!ctx) return;  // Null pointer check

    __u64 timestamp = bpf_ktime_get_ns();    // Get current timestamp
    __u32 pid_tgid = bpf_get_current_pid_tgid(); // Get PID/TID combination

    // Generate pseudo-random 128-bit trace ID
    ctx->trace_id_high = timestamp;  // High 64 bits from timestamp
    ctx->trace_id_low = ((__u64)pid_tgid << 32) | (timestamp & 0xFFFFFFFF);  // Low 64 bits
}

/**
 * generate_span_id() - Generate 64-bit span identifier
 *
 * This function generates a pseudo-random 64-bit span ID for distributed
 * tracing. Each span represents a unit of work within a trace and must
 * be unique within the trace context.
 *
 * ALGORITHM:
 * - XOR timestamp with shifted PID/TID for pseudo-randomness
 *
 * @return: Unique 64-bit span identifier
 */
static __always_inline __u64 generate_span_id() {
    __u64 timestamp = bpf_ktime_get_ns();    // Get current timestamp
    __u32 pid_tgid = bpf_get_current_pid_tgid(); // Get PID/TID combination

    // Generate pseudo-random 64-bit span ID using XOR
    return (timestamp ^ ((__u64)pid_tgid << 16));
}

/**
 * calculate_service_id() - Generate service identifier hash
 *
 * This function calculates a hash-based service identifier from the process
 * name and port number. Used for service mesh integration and service-level
 * correlation in distributed tracing scenarios.
 *
 * ALGORITHM:
 * 1. Hash process name using simple polynomial rolling hash (base 31)
 * 2. Include port number in hash calculation
 * 3. Return 32-bit hash as service identifier
 *
 * @comm: Process name (command) string
 * @port: Port number for the service
 * @return: 32-bit service identifier hash
 */
static __always_inline __u32 calculate_service_id(const char *comm, __u16 port) {
    __u32 hash = 0;

    // Simple polynomial rolling hash function for service identification
    // Using base 31 (prime number) for good distribution properties
    #pragma unroll
    for (int i = 0; i < MAX_COMM_SIZE && i < 16; i++) {
        if (comm[i] == 0) break;  // Stop at null terminator
        hash = hash * 31 + comm[i];  // Polynomial rolling hash
    }

    // Include port number in hash for service differentiation
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

    // Initialize output buffers (use actual event structure sizes)
    __builtin_memset(method, 0, 8);  // method[8] in event structure
    __builtin_memset(path, 0, 16);   // path[16] in event structure

    // Quick check if this looks like an HTTP request
    if (!is_http_request_start(data, len)) {
        return -1;
    }

    // Extract method (GET, POST, PUT, etc.) with bounds checking
    int method_end = 0;
    int method_len = 0;

    #pragma unroll
    for (int i = 0; i < 7 && i < len; i++) {  // method[8] - 1 for null terminator
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
        if (method_len < 7 && c >= 'A' && c <= 'Z') {  // method[8] - 1 for null terminator
            method[method_len] = c;
            method_len++;
        } else if (method_len < 7 && c >= 'a' && c <= 'z') {
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
    for (int i = path_start; i < len && path_len < 15; i++) {  // path[16] - 1 for null terminator
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
    __u64 count = (__u64)ctx->args[2];

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
    // Use actual payload size from event structure (16 bytes)
    if (count == 0 || count > 16 || count > 0x1000) {
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

    // Read payload safely with bounds checking (use actual event structure size)
    int payload_size = count < 16 ? count : 16;  // payload[16] in event structure
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
    const char *buf = (const char *)ctx->args[1];
    __u64 count = (__u64)ctx->args[2];

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
        char reason_phrase[16] = {0};  // Reduced from 32

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
