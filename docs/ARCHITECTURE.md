# Universal eBPF Tracer - Architecture Overview

## 🏗️ System Architecture

The Universal eBPF Tracer implements a multi-layer architecture that provides comprehensive observability across the entire system stack:

```
┌─────────────────────────────────────────────────────────────┐
│                    USER SPACE                               │
├─────────────────────────────────────────────────────────────┤
│  Go Userspace Agent                                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │HTTP Manager │ │ XDP Manager │ │Stack Manager│           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
│         │               │               │                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │           Ring Buffer Event Processing                  │ │
│  └─────────────────────────────────────────────────────────┘ │
│         │               │               │                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │         Correlation & Analytics Engine                 │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                   KERNEL SPACE                             │
├─────────────────────────────────────────────────────────────┤
│  eBPF Programs                                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │HTTP Tracer  │ │ XDP Tracer  │ │Stack Tracer │           │
│  │(Syscalls)   │ │(Network)    │ │(Profiling)  │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
│         │               │               │                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              eBPF Maps & Ring Buffers                  │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                 ATTACHMENT POINTS                          │
├─────────────────────────────────────────────────────────────┤
│  Syscalls    │    Network      │    Functions              │
│  • accept    │    • XDP Hook   │    • Kprobes              │
│  • read      │    • TC Hook    │    • Uprobes              │
│  • write     │    • Netfilter  │    • Tracepoints          │
│  • connect   │    • Socket     │    • Perf Events          │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔍 Component Deep Dive

### **1. HTTP Tracer Architecture**

```
Application Layer Tracing
┌─────────────────────────────────────────────────────────────┐
│                    HTTP Tracer                             │
├─────────────────────────────────────────────────────────────┤
│  Syscall Hooks                                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │sys_accept() │ │ sys_read()  │ │sys_write()  │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
│         │               │               │                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            Protocol Detection Engine                   │ │
│  │  • HTTP/HTTPS Parser                                   │ │
│  │  • gRPC Method Extractor                               │ │
│  │  • WebSocket Frame Detector                            │ │
│  └─────────────────────────────────────────────────────────┘ │
│         │                                                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │           Correlation Engine                           │ │
│  │  • Request-Response Matching                           │ │
│  │  • Connection Tracking                                 │ │
│  │  • Distributed Trace Propagation                      │ │
│  └─────────────────────────────────────────────────────────┘ │
│         │                                                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Event Generation                          │ │
│  │  • HTTP Events                                         │ │
│  │  • gRPC Events                                         │ │
│  │  • Performance Metrics                                 │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Key Data Structures**:
```c
struct http_event {
    __u64 timestamp;
    __u32 pid, tid;
    __u32 connection_id;
    __u32 request_id;
    char method[16];
    char path[256];
    __u16 status_code;
    __u64 latency_ns;
    char headers[512];
};

struct connection_info {
    __u32 fd;
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;
    __u64 start_time;
    __u32 request_count;
};
```

### **2. XDP Tracer Architecture**

```
Network Layer Tracing
┌─────────────────────────────────────────────────────────────┐
│                     XDP Tracer                            │
├─────────────────────────────────────────────────────────────┤
│  Network Hooks                                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ XDP Ingress │ │ TC Egress   │ │ Socket Hook │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
│         │               │               │                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │             Packet Parser                              │ │
│  │  • Ethernet Header                                     │ │
│  │  • IP Header (v4/v6)                                   │ │
│  │  • TCP/UDP Header                                      │ │
│  │  • Application Payload                                 │ │
│  └─────────────────────────────────────────────────────────┘ │
│         │                                                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            Flow Tracking                               │ │
│  │  • Connection State Machine                            │ │
│  │  • Flow Statistics                                     │ │
│  │  • Traffic Classification                              │ │
│  └─────────────────────────────────────────────────────────┘ │
│         │                                                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │           Network Analytics                            │ │
│  │  • Bandwidth Monitoring                                │ │
│  │  • Latency Measurement                                 │ │
│  │  • Error Detection                                     │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Key Data Structures**:
```c
struct xdp_event {
    __u64 timestamp;
    __u32 ifindex;
    __u16 packet_size;
    __u8 protocol;
    struct flow_key flow;
    __u8 is_http;
    char http_method[8];
    __u64 processing_time_ns;
    __u8 packet_data[256];
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
    __u32 tcp_flags;
    __u8 flow_state;
};
```

### **3. Stack Tracer Architecture**

```
Runtime & Profiling Layer
┌─────────────────────────────────────────────────────────────┐
│                   Stack Tracer                            │
├─────────────────────────────────────────────────────────────┤
│  Profiling Hooks                                           │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │  Kprobes    │ │  Uprobes    │ │Perf Events  │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
│         │               │               │                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            Stack Unwinding Engine                      │ │
│  │  • Frame Pointer Walking                               │ │
│  │  • DWARF Debug Info                                    │ │
│  │  • BTF Type Information                                │ │
│  └─────────────────────────────────────────────────────────┘ │
│         │                                                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │           Symbol Resolution                            │ │
│  │  • Function Names                                      │ │
│  │  • Source File/Line                                    │ │
│  │  • Module Information                                  │ │
│  └─────────────────────────────────────────────────────────┘ │
│         │                                                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            Analysis Engine                             │ │
│  │  • Flame Graph Generation                              │ │
│  │  • Deadlock Detection                                  │ │
│  │  • Memory Leak Analysis                                │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Key Data Structures**:
```c
struct stack_event {
    __u64 timestamp;
    __u32 pid, tid;
    __u32 stack_id;
    __u64 duration_ns;
    __u8 event_type;
    __u16 stack_depth;
    __u64 instruction_pointer;
    __u32 request_id;
};

struct stack_frame {
    __u64 ip;
    __u64 sp;
    __u32 function_id;
    char symbol[64];
};
```

---

## 🔄 Data Flow Architecture

### **Event Processing Pipeline**

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   eBPF      │    │    Ring     │    │ Userspace   │
│  Programs   │───▶│   Buffer    │───▶│   Agent     │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Event     │    │   Batch     │    │Correlation  │
│Generation   │    │Processing   │    │  Engine     │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Maps      │    │   Memory    │    │  Analytics  │
│  Storage    │    │   Pool      │    │   Output    │
└─────────────┘    └─────────────┘    └─────────────┘
```

### **Correlation Architecture**

```
Cross-Layer Event Correlation
┌─────────────────────────────────────────────────────────────┐
│                Correlation Engine                          │
├─────────────────────────────────────────────────────────────┤
│  Input Streams                                              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │HTTP Events  │ │ XDP Events  │ │Stack Events │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
│         │               │               │                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            Temporal Correlation                        │ │
│  │  • Timestamp Alignment                                 │ │
│  │  • Event Ordering                                      │ │
│  │  • Causality Detection                                 │ │
│  └─────────────────────────────────────────────────────────┘ │
│         │                                                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │           Contextual Correlation                       │ │
│  │  • Process/Thread Matching                             │ │
│  │  • Connection Tracking                                 │ │
│  │  • Request ID Propagation                              │ │
│  └─────────────────────────────────────────────────────────┘ │
│         │                                                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            Trace Construction                          │ │
│  │  • Span Creation                                       │ │
│  │  • Trace Assembly                                      │ │
│  │  • Distributed Tracing                                 │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 🗺️ eBPF Maps Architecture

### **Map Types and Usage**

```c
// HTTP Tracer Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} http_events;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct connection_info);
} connections;

// XDP Tracer Maps  
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flow_table;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_counter;

// Stack Tracer Maps
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
} stack_traces;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, struct stack_context);
} process_stacks;
```

### **Memory Layout**

```
eBPF Map Memory Organization
┌─────────────────────────────────────────────────────────────┐
│                    Kernel Memory                           │
├─────────────────────────────────────────────────────────────┤
│  Ring Buffers (Event Streaming)                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │HTTP Events  │ │ XDP Events  │ │Stack Events │           │
│  │   256KB     │ │   256KB     │ │   256KB     │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
├─────────────────────────────────────────────────────────────┤
│  Hash Maps (State Storage)                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │Connections  │ │Flow Table   │ │Stack Traces │           │
│  │   ~400KB    │ │   ~2MB      │ │   ~5MB      │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
├─────────────────────────────────────────────────────────────┤
│  Per-CPU Arrays (Counters)                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │HTTP Stats   │ │Network Stats│ │Profile Stats│           │
│  │   ~8KB      │ │   ~16KB     │ │   ~32KB     │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────┘
Total Kernel Memory: ~8MB (configurable)
```

---

## ⚡ Performance Architecture

### **Optimization Strategies**

1. **Zero-Copy Data Path**
   - Ring buffers for event streaming
   - Direct memory mapping
   - Batch processing

2. **Efficient Filtering**
   - Kernel-space filtering
   - Early packet drops
   - Sampling strategies

3. **Lock-Free Operations**
   - Per-CPU data structures
   - Atomic operations
   - RCU synchronization

4. **Memory Management**
   - Pre-allocated buffers
   - Object pooling
   - Garbage collection optimization

### **Scalability Metrics**

```
Performance Characteristics
┌─────────────────────────────────────────────────────────────┐
│  Component     │ Throughput    │ Latency      │ CPU Usage   │
├─────────────────────────────────────────────────────────────┤
│  HTTP Tracer   │ 100K req/s    │ <100μs       │ <3%         │
│  XDP Tracer    │ 10M pkt/s     │ <1μs         │ <2%         │
│  Stack Tracer  │ 1K samples/s  │ <500μs       │ <5%         │
├─────────────────────────────────────────────────────────────┤
│  Total System  │ Combined      │ <1ms         │ <10%        │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔒 Security Architecture

### **Privilege Separation**

```
Security Boundaries
┌─────────────────────────────────────────────────────────────┐
│                   User Space                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │           Unprivileged Components                      │ │
│  │  • Data Processing                                     │ │
│  │  • Analytics Engine                                    │ │
│  │  • Output Generation                                   │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                  Kernel Space                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            Privileged Components                       │ │
│  │  • eBPF Program Loading                                │ │
│  │  • Map Creation/Access                                 │ │
│  │  • Network Interface Attachment                        │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### **Data Protection**

- **In-Transit**: TLS encryption for remote endpoints
- **At-Rest**: Optional encryption for stored traces
- **In-Memory**: Memory protection and isolation
- **PII Filtering**: Automatic sensitive data redaction

---

## 🎯 Summary

The Universal eBPF Tracer architecture provides:

- **Multi-Layer Observability**: Network, Application, and Runtime layers
- **High Performance**: Optimized for production workloads
- **Scalable Design**: Handles enterprise-scale traffic
- **Security-First**: Privilege separation and data protection
- **Extensible Framework**: Modular design for future enhancements

This architecture enables comprehensive, universal tracing with minimal overhead and maximum insight across any application stack.
