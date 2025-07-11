# eBPF HTTP Tracing PoC

A high-performance, eBPF-based distributed tracing system that traces HTTP requests from client through backend services without requiring application code modifications.

## 🎯 Overview

This PoC demonstrates:
- **Kernel-space eBPF tracer** that hooks into `accept()`, `read()`, and `connect()` syscalls
- **Userspace Go agent** that processes events and outputs structured JSON logs
- **Runtime-agnostic tracing** that works with any HTTP server stack
- **Plaintext HTTP request detection** with method/path extraction
- **Test environment** with Flask server and automated test scripts

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   HTTP Client   │───▶│   Target Server  │───▶│   Backend DB    │
│    (curl)       │    │   (Flask/Any)    │    │   (SQLite)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌──────────────────────┐
                    │   eBPF Kernel Hooks  │
                    │  accept() read()     │
                    │  connect()           │
                    └──────────────────────┘
                                 │
                                 ▼
                    ┌──────────────────────┐
                    │   Ring Buffer        │
                    └──────────────────────┘
                                 │
                                 ▼
                    ┌──────────────────────┐
                    │   Go Userspace       │
                    │   Agent              │
                    └──────────────────────┘
                                 │
                                 ▼
                    ┌──────────────────────┐
                    │   JSON Logs          │
                    │   (stdout)           │
                    └──────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Linux kernel 4.18+ with eBPF support
- Root privileges (for loading eBPF programs)
- clang/LLVM
- Go 1.21+
- Python 3.8+ (for test server)

### Installation

1. **Install system dependencies** (Ubuntu/Debian):
   ```bash
   make install-system-deps
   ```

2. **Install project dependencies**:
   ```bash
   make deps
   ```

3. **Check system requirements**:
   ```bash
   make check-system
   ```

4. **Build the project**:
   ```bash
   make all
   ```

### Running the PoC

1. **Terminal 1** - Start the test server:
   ```bash
   make test-server
   ```

2. **Terminal 2** - Run the eBPF tracer (requires root):
   ```bash
   sudo make run
   ```

3. **Terminal 3** - Generate test traffic:
   ```bash
   make test
   ```

You should see JSON-formatted trace events in Terminal 2 showing HTTP requests being captured!

## 📊 Sample Output

```json
{
  "timestamp": "2024-01-15T10:30:45.123456789Z",
  "pid": 12345,
  "tid": 12345,
  "src_ip": "",
  "dst_ip": "",
  "src_port": 0,
  "dst_port": 0,
  "comm": "python3",
  "method": "GET",
  "path": "/users",
  "payload_len": 85,
  "payload": "GET /users HTTP/1.1\r\nHost: localhost:5000\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n",
  "event_type": "read",
  "event_type_id": 1
}
```

## 🔧 Components

### 1. eBPF Kernel Program (`src/http_tracer.c`)

- **Hooks**: `accept()`, `read()`, `connect()` syscalls via tracepoints
- **Event Structure**: Captures timestamp, PID, command, HTTP method/path, payload
- **HTTP Parsing**: Safely extracts method and path from socket data
- **Ring Buffer**: Efficiently passes events to userspace

### 2. Go Userspace Agent (`cmd/tracer/main.go`)

- **eBPF Loading**: Uses cilium/ebpf library to load and attach programs
- **Event Processing**: Reads from ring buffer and converts to JSON
- **Filtering**: Only outputs HTTP requests (read events with method/path)
- **Signal Handling**: Graceful shutdown on Ctrl+C

### 3. Test Environment (`test/`)

- **Flask Server**: Simulates realistic backend with DB operations
- **Test Scripts**: Automated HTTP request generation
- **Multiple Endpoints**: Various request types (GET, POST, slow, external)

## 🛡️ Safety Considerations

### eBPF Verifier Compliance

The eBPF program is designed to pass kernel verifier checks:

- **Bounded Loops**: No unbounded loops in HTTP parsing
- **Memory Safety**: All memory accesses are bounds-checked
- **Stack Limits**: Payload size limited to 256 bytes
- **Helper Usage**: Only uses allowed eBPF helpers

### HTTP Payload Extraction

```c
// Safe payload reading with bounds checking
int payload_size = count < MAX_PAYLOAD_SIZE ? count : MAX_PAYLOAD_SIZE;
if (bpf_probe_read_user(event->payload, payload_size, buf) == 0) {
    // Parse HTTP safely with length limits
    parse_http_request(event->payload, payload_size, event->method, event->path);
}
```

## 🔄 Correlation Strategy

### Current Implementation
- Tracks socket file descriptors in `sock_info` map
- Associates `accept()` events with subsequent `read()` events
- Captures `connect()` events for outbound connections

### Next Steps for Full Correlation

1. **5-Tuple Matching**:
   ```c
   struct connection_key {
       __u32 src_ip, dst_ip;
       __u16 src_port, dst_port;
       __u8 protocol;
   };
   ```

2. **Request Context Tracking**:
   - Generate unique request IDs
   - Track request lifecycle across syscalls
   - Correlate inbound HTTP with outbound DB/API calls

3. **Timing Analysis**:
   - Measure end-to-end latency
   - Identify bottlenecks in request processing

## 📋 Available Make Targets

```bash
make help                 # Show all available targets
make deps                 # Install dependencies
make all                  # Build the project
make check-system         # Verify system requirements
make run                  # Run tracer (requires root)
make test-server          # Start Flask test server
make test                 # Run simple tests
make test-full            # Run comprehensive tests
make clean                # Clean build artifacts
```

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied**:
   ```bash
   sudo make run  # eBPF requires root privileges
   ```

2. **Tracepoint Not Found**:
   ```bash
   # Check if tracepoints are available
   ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_*
   ```

3. **eBPF Program Load Failed**:
   ```bash
   # Check kernel version and eBPF support
   uname -r
   zgrep CONFIG_BPF /proc/config.gz
   ```

4. **No Events Captured**:
   - Ensure test server is running on port 5000
   - Check that HTTP requests are being made
   - Verify eBPF program is attached: `bpftool prog list`

### Debug Mode

Enable verbose logging:
```bash
# Add debug prints to Go program
GODEBUG=gctrace=1 sudo ./build/http-tracer
```

## 🚧 Limitations & Future Work

### Current Limitations
- **Plaintext HTTP only** (no HTTPS/TLS support)
- **Limited payload parsing** (basic method/path extraction)
- **No request correlation** across multiple connections
- **Single-node tracing** (no distributed correlation)

### Planned Enhancements
- [ ] HTTPS/TLS support via uprobes
- [ ] Request ID generation and propagation
- [ ] Database query correlation
- [ ] Distributed tracing integration
- [ ] Performance metrics and alerting
- [ ] Web UI for trace visualization

## 📄 License

This project is licensed under the GPL License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For questions or issues:
- Create an issue in the repository
- Check the troubleshooting section
- Review eBPF documentation: https://ebpf.io/
