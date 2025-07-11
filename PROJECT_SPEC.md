# eBPF Tracer Project Specification

## Executive Summary

This project implements a comprehensive eBPF-based distributed tracing system that provides cross-language, cross-platform monitoring of HTTP/gRPC requests without requiring application code modifications. The system focuses on production-grade performance, security, and scalability requirements.

## Project Scope

### Core Objectives
1. **Universal Tracing**: Cross-language and cross-platform monitoring without source code modifications
2. **Production Ready**: High-performance, low-overhead tracing suitable for production environments
3. **Distributed Correlation**: End-to-end request tracing across microservices
4. **Security Compliant**: Works with Secure Boot and strict security policies
5. **Observability Integration**: Compatible with OpenTelemetry, Jaeger, Prometheus, Grafana

### Technical Requirements

#### MVP (Minimum Viable Product)
- [x] **Function Entry/Exit Tracing**: kprobe/uprobe mechanisms with PID/namespace filtering
- [x] **Function Arguments Collection**: Safe extraction of primitive types and basic structures
- [x] **Accurate Latency Measurement**: High-precision timestamps with bpf_ktime_get_ns()
- [x] **Reliable Data Transfer**: Ring buffer implementation for userspace communication
- [x] **Call Stack Reconstruction**: Frame pointer parsing with DWARF fallback

#### Advanced Features
- [ ] **HTTP/gRPC Request Correlation**: Automatic trace-id extraction and injection
- [ ] **Asynchronous Context Handling**: Support for goroutines, threads, async operations
- [ ] **Advanced Filtering**: Dynamic sampling, URL/method filtering, PID-based filtering
- [ ] **Multiple Export Formats**: JSON, protobuf, OpenTelemetry Trace compatibility
- [ ] **BTF/DWARF Integration**: Symbol recovery for stripped binaries

#### Non-Functional Requirements
- **Performance**: <5% CPU overhead, <100MB memory footprint
- **Security**: Secure Boot compatibility, minimal privileges after bootstrap
- **Scalability**: Support for 10k+ events/second, horizontal scaling
- **Reliability**: 99.9% uptime, graceful degradation under load
- **Portability**: CO-RE compatibility across kernel versions 4.18+

## Current Implementation Status

### Completed Components
1. **eBPF Kernel Program** (`src/http_tracer.c`)
   - Syscall tracepoints: accept(), read(), connect()
   - HTTP request parsing and method/path extraction
   - Ring buffer event transmission
   - Basic request correlation via PID tracking

2. **Go Userspace Agent** (`cmd/tracer/main.go`)
   - eBPF program loading and attachment
   - Ring buffer event processing
   - JSON output formatting
   - Signal handling and graceful shutdown

3. **Build System** (`Makefile`)
   - eBPF compilation with clang
   - Go binary building
   - System dependency checking
   - Test automation

4. **Test Environment** (`test/`)
   - Flask test server
   - Automated HTTP request generation
   - Basic integration testing

### Architecture Overview

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
                    │  connect() write()   │
                    └──────────────────────┘
                                 │
                                 ▼
                    ┌──────────────────────┐
                    │   Ring Buffer        │
                    │   (256KB)            │
                    └──────────────────────┘
                                 │
                                 ▼
                    ┌──────────────────────┐
                    │   Go Userspace       │
                    │   Agent              │
                    │   - Event Processing │
                    │   - Correlation      │
                    │   - Export           │
                    └──────────────────────┘
                                 │
                                 ▼
                    ┌──────────────────────┐
                    │   Output Formats     │
                    │   - JSON Logs        │
                    │   - OpenTelemetry    │
                    │   - Jaeger           │
                    └──────────────────────┘
```

## Technology Stack

### Kernel Space
- **Language**: C with eBPF
- **Compilation**: Clang/LLVM with CO-RE support
- **Hooks**: kprobe, uprobe, tracepoint, fentry/fexit
- **Data Structures**: BPF maps (hash, array, ring buffer)
- **Compatibility**: BTF metadata for kernel portability

### User Space
- **Language**: Go 1.21+
- **Libraries**:
  - github.com/cilium/ebpf (eBPF loading/management)
  - Standard library for JSON/HTTP
- **Architecture**: Event-driven processing with goroutines

### Infrastructure
- **Build System**: Make with multi-target support
- **Testing**: Automated integration tests with Flask
- **CI/CD**: GitHub Actions with multi-kernel testing
- **Deployment**: Systemd units, Kubernetes Helm charts

## Key Design Decisions

### 1. Ring Buffer vs Perf Buffer
- **Choice**: Ring buffer (kernel 5.8+) with perf buffer fallback
- **Rationale**: Better performance, lower latency, built-in backpressure

### 2. Tracepoints vs kprobes
- **Choice**: Tracepoints for syscalls, kprobes for kernel functions
- **Rationale**: Tracepoints are more stable across kernel versions

### 3. CO-RE (Compile Once, Run Everywhere)
- **Choice**: BTF-based CO-RE for portability
- **Rationale**: Eliminates need for kernel headers on target systems

### 4. Event Correlation Strategy
- **Current**: PID-based correlation with socket FD tracking
- **Future**: 5-tuple network correlation + trace-id propagation

## Risk Assessment

### High Risk
1. **Kernel Compatibility**: eBPF API changes across kernel versions
2. **Security Restrictions**: Secure Boot limitations on eBPF helpers
3. **Performance Impact**: Overhead in high-throughput environments

### Medium Risk
1. **Memory Constraints**: BPF map size limitations
2. **Verifier Complexity**: eBPF program complexity limits
3. **Deployment Complexity**: Root privileges requirement

### Low Risk
1. **Go Dependencies**: Stable ecosystem
2. **Build System**: Well-established toolchain
3. **Testing Infrastructure**: Mature testing frameworks

## Success Metrics

### Performance Metrics
- CPU overhead: <5% under normal load
- Memory usage: <100MB for userspace agent
- Event throughput: >10,000 events/second
- Latency impact: <1ms additional latency

### Functional Metrics
- HTTP request detection accuracy: >95%
- Correlation success rate: >90%
- System stability: 99.9% uptime
- Cross-platform compatibility: 5+ Linux distributions

### Operational Metrics
- Deployment time: <5 minutes
- Configuration complexity: <10 parameters
- Troubleshooting time: <30 minutes for common issues
- Documentation completeness: 100% API coverage

## Implementation Phases

### Phase I: Foundation & MVP Enhancement (2-3 weeks)
- Enhance current eBPF program with better error handling
- Improve HTTP parsing robustness
- Add comprehensive unit tests
- Implement basic performance benchmarking

### Phase II: Advanced Correlation (3-4 weeks)
- Implement 5-tuple network correlation
- Add trace-id generation and propagation
- Support for HTTP/gRPC request correlation
- Asynchronous context handling

### Phase III: Production Features (3-4 weeks)
- Advanced filtering and sampling
- Multiple export formats (OpenTelemetry, Jaeger)
- Performance optimization
- Security hardening

### Phase IV: Deployment & Operations (2-3 weeks)
- CI/CD pipeline implementation
- Kubernetes deployment manifests
- Monitoring and alerting integration
- Documentation and examples