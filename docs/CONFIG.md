# Universal eBPF Tracer - Configuration Reference

## 📋 Configuration Overview

The Universal eBPF Tracer supports multiple configuration methods:

1. **YAML Configuration Files** - Primary configuration method
2. **Command Line Arguments** - Override specific settings
3. **Environment Variables** - Container-friendly configuration
4. **Runtime API** - Dynamic configuration updates

---

## 🔧 Configuration File Structure

### **Complete Configuration Example**

```yaml
# config/universal-tracer.yaml
global:
  log_level: info                    # debug, info, warn, error
  log_format: json                   # json, text
  output_format: json                # json, text, protobuf
  output_file: "/var/log/tracer.log"
  metrics_enabled: true
  metrics_endpoint: ":9090/metrics"
  pprof_enabled: false
  pprof_endpoint: ":6060"

# HTTP/Application Layer Tracing
http_tracer:
  enabled: true
  interfaces: ["eth0", "lo"]
  enable_correlation: true
  enable_grpc: true
  enable_websocket: true
  enable_distributed_tracing: true
  
  # Protocol Configuration
  protocols:
    http:
      enabled: true
      ports: [80, 8080, 3000, 5000]
      max_payload_size: 4096
      capture_headers: true
      capture_body: false
    https:
      enabled: true
      ports: [443, 8443]
      max_payload_size: 1024
      capture_headers: true
      capture_body: false
    grpc:
      enabled: true
      ports: [9090, 50051]
      capture_metadata: true
      capture_messages: false
    websocket:
      enabled: true
      ports: [8080, 3000]
      capture_frames: true
      max_frame_size: 1024
  
  # Sampling and Filtering
  sampling:
    rate: 1.0                        # 0.0 to 1.0
    max_events_per_second: 10000
    burst_limit: 1000
  
  filtering:
    enable_pii_filtering: true
    exclude_paths:
      - "/health"
      - "/metrics"
      - "/favicon.ico"
    exclude_headers:
      - "authorization"
      - "cookie"
      - "x-api-key"
    exclude_user_agents:
      - "kube-probe"
      - "prometheus"
  
  # Correlation Settings
  correlation:
    timeout: 30s
    max_concurrent_requests: 10000
    trace_header: "X-Trace-ID"
    span_header: "X-Span-ID"
    parent_span_header: "X-Parent-Span-ID"
    
  # Performance Tuning
  performance:
    ring_buffer_size: 262144         # 256KB
    map_size_connections: 10000
    map_size_requests: 50000
    batch_size: 100
    flush_interval: 1s

# Network Layer Tracing  
xdp_tracer:
  enabled: true
  interfaces: ["eth0", "eth1"]
  mode: "generic"                    # generic, native, offload
  
  # Packet Processing
  packet_processing:
    enable_http_detection: true
    enable_flow_tracking: true
    enable_packet_capture: false
    max_packet_size: 1500
    capture_payload_size: 256
  
  # Flow Tracking
  flow_tracking:
    flow_table_size: 65536
    flow_timeout: 300s
    enable_tcp_state_tracking: true
    enable_connection_metrics: true
  
  # Sampling and Filtering
  sampling:
    rate: 1                          # 1 = every packet, 10 = every 10th packet
    max_packets_per_second: 1000000
    burst_limit: 10000
  
  filtering:
    protocols: ["tcp", "udp"]
    ports: [80, 443, 8080, 9090]
    exclude_local_traffic: false
    exclude_broadcast: true
  
  # Performance Tuning
  performance:
    ring_buffer_size: 262144         # 256KB
    num_rx_queues: 4
    batch_size: 64
    poll_timeout: 1000               # microseconds

# Runtime/Stack Tracing
stack_tracer:
  enabled: true
  
  # Stack Collection
  stack_collection:
    enable_kernel_stacks: true
    enable_user_stacks: true
    enable_mixed_stacks: true
    max_stack_depth: 127
    sampling_frequency: 99           # Hz
  
  # Symbol Resolution
  symbol_resolution:
    enable_dwarf_unwinding: true
    enable_frame_pointers: true
    symbol_cache_size: 100000
    symbol_paths:
      - "/usr/lib/debug"
      - "/proc/kallsyms"
      - "/sys/kernel/btf/vmlinux"
  
  # Target Configuration
  targets:
    processes: ["nginx", "python3", "java", "node"]
    containers: []
    pids: []
    exclude_kernel_threads: true
  
  # Profiling Modes
  profiling:
    enable_cpu_profiling: true
    enable_memory_profiling: true
    enable_deadlock_detection: true
    enable_flame_graphs: true
    
    cpu_profiling:
      sampling_rate: 99
      duration: 60s
      output_format: "flamegraph"
    
    memory_profiling:
      allocation_threshold: 1048576  # 1MB
      track_allocations: true
      track_deallocations: true
  
  # Performance Tuning
  performance:
    ring_buffer_size: 262144         # 256KB
    stack_map_size: 10000
    max_events_per_second: 1000
    batch_size: 50

# Security Configuration
security:
  enable_privilege_dropping: true
  run_as_user: "tracer"
  run_as_group: "tracer"
  
  # Data Protection
  data_protection:
    enable_encryption: false
    encryption_key_file: "/etc/tracer/key"
    enable_pii_filtering: true
    pii_patterns:
      - "password"
      - "token"
      - "secret"
      - "key"
      - "auth"
  
  # Access Control
  access_control:
    enable_rbac: false
    allowed_users: ["tracer", "admin"]
    allowed_groups: ["tracing", "monitoring"]

# Output Configuration
output:
  # File Output
  file:
    enabled: true
    path: "/var/log/ebpf-tracer"
    rotation:
      max_size: "100MB"
      max_files: 10
      max_age: "7d"
  
  # Streaming Output
  kafka:
    enabled: false
    brokers: ["localhost:9092"]
    topic: "ebpf-traces"
    compression: "gzip"
  
  elasticsearch:
    enabled: false
    endpoints: ["http://localhost:9200"]
    index_pattern: "ebpf-traces-%{+YYYY.MM.dd}"
  
  jaeger:
    enabled: false
    endpoint: "http://localhost:14268/api/traces"
    service_name: "ebpf-tracer"
  
  prometheus:
    enabled: true
    endpoint: ":9090/metrics"
    push_gateway: ""

# Monitoring and Alerting
monitoring:
  health_check:
    enabled: true
    endpoint: ":8080/health"
    interval: 30s
  
  metrics:
    collection_interval: 10s
    retention_period: "24h"
    
  alerts:
    high_cpu_usage: 80
    high_memory_usage: 85
    high_event_rate: 50000
    low_event_rate: 10
```

---

## 🌍 Environment Variables

### **Global Settings**
```bash
# Logging
TRACER_LOG_LEVEL=info
TRACER_LOG_FORMAT=json
TRACER_OUTPUT_FORMAT=json

# Metrics
TRACER_METRICS_ENABLED=true
TRACER_METRICS_ENDPOINT=:9090/metrics

# Security
TRACER_ENABLE_PII_FILTERING=true
TRACER_RUN_AS_USER=tracer
```

### **HTTP Tracer Settings**
```bash
# Basic Configuration
TRACER_HTTP_ENABLED=true
TRACER_HTTP_INTERFACES=eth0,lo
TRACER_HTTP_SAMPLING_RATE=1.0

# Protocol Settings
TRACER_HTTP_ENABLE_GRPC=true
TRACER_HTTP_ENABLE_WEBSOCKET=true
TRACER_HTTP_MAX_PAYLOAD_SIZE=4096

# Correlation
TRACER_HTTP_TRACE_HEADER=X-Trace-ID
TRACER_HTTP_SPAN_HEADER=X-Span-ID
```

### **XDP Tracer Settings**
```bash
# Basic Configuration
TRACER_XDP_ENABLED=true
TRACER_XDP_INTERFACES=eth0,eth1
TRACER_XDP_MODE=generic

# Flow Tracking
TRACER_XDP_FLOW_TABLE_SIZE=65536
TRACER_XDP_FLOW_TIMEOUT=300s
TRACER_XDP_SAMPLING_RATE=1
```

### **Stack Tracer Settings**
```bash
# Basic Configuration
TRACER_STACK_ENABLED=true
TRACER_STACK_SAMPLING_FREQUENCY=99
TRACER_STACK_MAX_DEPTH=127

# Symbol Resolution
TRACER_STACK_ENABLE_DWARF=true
TRACER_STACK_ENABLE_FRAME_POINTERS=true
TRACER_STACK_SYMBOL_CACHE_SIZE=100000

# Targets
TRACER_STACK_TARGET_PROCESSES=nginx,python3,java
```

---

## 🚀 Command Line Arguments

### **Global Options**
```bash
./universal-tracer \
  --config /etc/tracer/config.yaml \
  --log-level info \
  --log-format json \
  --output-format json \
  --output-file /var/log/tracer.log \
  --metrics-endpoint :9090/metrics \
  --health-endpoint :8080/health
```

### **Tracer-Specific Options**
```bash
# HTTP Tracer
./universal-tracer \
  --tracer http \
  --interface eth0 \
  --enable-correlation \
  --enable-grpc \
  --sampling-rate 0.1 \
  --max-payload-size 1024

# XDP Tracer  
./universal-tracer \
  --tracer xdp \
  --interface eth0 \
  --xdp-mode native \
  --enable-flow-tracking \
  --flow-table-size 32768 \
  --sampling-rate 10

# Stack Tracer
./universal-tracer \
  --tracer stack \
  --target-process nginx \
  --sampling-frequency 49 \
  --enable-dwarf \
  --max-stack-depth 64 \
  --duration 60s
```

### **Combined Tracers**
```bash
# Run all tracers
./universal-tracer \
  --tracer http,xdp,stack \
  --interface eth0 \
  --config /etc/tracer/production.yaml \
  --output-file /var/log/all-traces.json
```

---

## 🎛️ Runtime Configuration

### **Configuration API**
```bash
# Get current configuration
curl http://localhost:8080/api/v1/config

# Update HTTP tracer sampling rate
curl -X PUT http://localhost:8080/api/v1/config/http/sampling/rate \
  -H "Content-Type: application/json" \
  -d '{"rate": 0.5}'

# Enable/disable specific tracer
curl -X PUT http://localhost:8080/api/v1/config/xdp/enabled \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# Update target processes for stack tracer
curl -X PUT http://localhost:8080/api/v1/config/stack/targets/processes \
  -H "Content-Type: application/json" \
  -d '{"processes": ["nginx", "python3", "java", "node"]}'
```

### **Configuration Validation**
```bash
# Validate configuration file
./universal-tracer --config config.yaml --validate

# Test configuration without starting
./universal-tracer --config config.yaml --dry-run

# Show effective configuration
./universal-tracer --config config.yaml --show-config
```

---

## 📊 Performance Tuning

### **Memory Optimization**
```yaml
# Low memory configuration
performance:
  http_tracer:
    ring_buffer_size: 65536          # 64KB
    map_size_connections: 1000
    map_size_requests: 5000
  
  xdp_tracer:
    ring_buffer_size: 65536          # 64KB
    flow_table_size: 16384
  
  stack_tracer:
    ring_buffer_size: 65536          # 64KB
    stack_map_size: 1000
    symbol_cache_size: 10000
```

### **High Throughput Configuration**
```yaml
# High throughput configuration
performance:
  http_tracer:
    ring_buffer_size: 1048576        # 1MB
    batch_size: 1000
    flush_interval: 100ms
  
  xdp_tracer:
    ring_buffer_size: 1048576        # 1MB
    flow_table_size: 131072
    batch_size: 256
  
  stack_tracer:
    ring_buffer_size: 524288         # 512KB
    sampling_frequency: 199
    batch_size: 200
```

### **CPU Optimization**
```yaml
# CPU optimized configuration
performance:
  global:
    worker_threads: 8
    cpu_affinity: [0, 1, 2, 3]
  
  sampling:
    http_rate: 0.01                  # 1% sampling
    xdp_rate: 100                    # Every 100th packet
    stack_frequency: 19              # 19Hz sampling
```

---

## 🔒 Security Configuration

### **Privilege Dropping**
```yaml
security:
  enable_privilege_dropping: true
  run_as_user: "tracer"
  run_as_group: "tracer"
  capabilities:
    - "CAP_SYS_ADMIN"
    - "CAP_NET_ADMIN"
    - "CAP_BPF"
```

### **Data Protection**
```yaml
security:
  data_protection:
    enable_encryption: true
    encryption_algorithm: "AES-256-GCM"
    key_rotation_interval: "24h"
    
    pii_filtering:
      enabled: true
      patterns:
        - "(?i)password"
        - "(?i)token"
        - "(?i)secret"
        - "(?i)api[_-]?key"
        - "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"  # Credit cards
        - "\\b\\d{3}-\\d{2}-\\d{4}\\b"                            # SSN
```

---

## 📋 Configuration Templates

### **Development Environment**
```yaml
# config/development.yaml
global:
  log_level: debug
  output_format: json

http_tracer:
  enabled: true
  interfaces: ["lo"]
  sampling: { rate: 1.0 }
  
xdp_tracer:
  enabled: false
  
stack_tracer:
  enabled: true
  targets: { processes: ["python3", "node"] }
  profiling: { sampling_rate: 19 }
```

### **Production Environment**
```yaml
# config/production.yaml
global:
  log_level: info
  metrics_enabled: true

http_tracer:
  enabled: true
  interfaces: ["eth0"]
  sampling: { rate: 0.1 }
  filtering: { enable_pii_filtering: true }
  
xdp_tracer:
  enabled: true
  interfaces: ["eth0", "eth1"]
  sampling: { rate: 100 }
  
stack_tracer:
  enabled: true
  profiling: { sampling_rate: 99 }
  performance: { max_events_per_second: 1000 }
```

### **Container Environment**
```yaml
# config/container.yaml
global:
  log_format: json
  output_format: json

http_tracer:
  enabled: true
  interfaces: ["eth0"]
  
output:
  kafka:
    enabled: true
    brokers: ["kafka:9092"]
    topic: "traces"
```

---

## ✅ Configuration Validation

### **Required Settings**
- At least one tracer must be enabled
- Valid network interfaces must be specified
- Output configuration must be valid
- Security settings must be consistent

### **Validation Commands**
```bash
# Validate configuration
./universal-tracer --validate --config config.yaml

# Show configuration schema
./universal-tracer --schema

# Generate sample configuration
./universal-tracer --generate-config > sample-config.yaml
```

This comprehensive configuration reference enables fine-tuned control over all aspects of the Universal eBPF Tracer for any deployment scenario.
