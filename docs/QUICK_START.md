# Universal eBPF Tracer - Quick Start Guide

## 🚀 5-Minute Setup

### **Prerequisites Check**
```bash
# Check kernel version (5.4+ required)
uname -r

# Check if running as root or with sudo
whoami

# Verify basic tools
which clang llvm go make
```

### **1. Install Dependencies**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) build-essential golang-go

# RHEL/CentOS/Fedora  
sudo dnf install -y clang llvm libbpf-devel kernel-headers kernel-devel gcc make golang

# Arch Linux
sudo pacman -S clang llvm libbpf linux-headers base-devel go
```

### **2. Build the Tracers**
```bash
# Clone and build
git clone https://github.com/mexyusef/ebpf-tracing.git
cd ebpf-tracing

# Compile eBPF programs
make clean && make ebpf

# Build userspace components
make build

# Verify build
ls -la *.o build/
```

#### Example output
```bash
user@firebase-elodie-1748856286420:~/ebpf$ make clean
Cleaning build artifacts...
rm -f http_tracer.o xdp_tracer.o stack_tracer.o
rm -rf build
go clean
user@firebase-elodie-1748856286420:~/ebpf$ make ebpf
Compiling HTTP tracer eBPF program...
clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -mllvm -bpf-stack-size=8192 -Wno-pass-failed -c src/http_tracer.c -o http_tracer.o
Compiling XDP tracer eBPF program...
clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -mllvm -bpf-stack-size=8192 -Wno-pass-failed -c src/xdp_tracer.c -o xdp_tracer.o
Compiling Stack tracer eBPF program...
clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -mllvm -bpf-stack-size=8192 -Wno-pass-failed -c src/stack_tracer.c -o stack_tracer.o
All eBPF programs compiled successfully!
user@firebase-elodie-1748856286420:~/ebpf$ make build
mkdir -p build
user@firebase-elodie-1748856286420:~/ebpf$ ls -la *.o build/
-rw-rw-r-- 1 user user 34840 Jul 12 17:25 http_tracer.o
-rw-rw-r-- 1 user user 59256 Jul 12 17:25 stack_tracer.o
-rw-rw-r-- 1 user user 62496 Jul 12 17:25 xdp_tracer.o

build/:
total 8
drwxrwxr-x  2 user user 4096 Jul 12 17:25 .
drwxrwxr-x 16 user user 4096 Jul 12 17:25 ..
user@firebase-elodie-1748856286420:~/ebpf$ 
```

### **3. Quick Test**
```bash
# Test HTTP tracing (monitors localhost HTTP traffic)
sudo ./build/universal-tracer --tracer http --interface lo --duration 30s

# In another terminal, generate some HTTP traffic
curl http://localhost:8080/test
wget http://httpbin.org/get

# Test XDP network tracing
sudo ./build/universal-tracer --tracer xdp --interface eth0 --duration 10s

# Test stack profiling
sudo ./build/universal-tracer --tracer stack --target-process nginx --duration 60s
```

---

## 📊 Common Use Cases

### **Web Application Monitoring**
```bash
# Monitor HTTP/HTTPS traffic for a web application
sudo ./build/universal-tracer \
  --tracer http \
  --interface eth0 \
  --enable-correlation \
  --output web-app-traces.json

# View results
cat web-app-traces.json | jq '.[] | select(.status_code >= 400)'
```

### **Microservices Distributed Tracing**
```bash
# Enable distributed tracing across services
sudo ./build/universal-tracer \
  --tracer http \
  --enable-distributed-tracing \
  --trace-header "X-Trace-ID" \
  --jaeger-endpoint "http://jaeger:14268/api/traces"
```

### **Network Performance Analysis**
```bash
# High-frequency network monitoring
sudo ./build/universal-tracer \
  --tracer xdp \
  --interface eth0 \
  --enable-flow-tracking \
  --output network-flows.json

# Analyze top talkers
cat network-flows.json | jq -r '.[] | "\(.src_ip):\(.src_port) -> \(.dst_ip):\(.dst_port) (\(.bytes) bytes)"' | sort -k3 -nr | head -10
```

### **Application Performance Profiling**
```bash
# Generate flame graph for performance analysis
sudo ./build/universal-tracer \
  --tracer stack \
  --target-process "python3" \
  --sampling-frequency 99 \
  --duration 60s \
  --output flamegraph.svg

# Memory allocation profiling
sudo ./build/universal-tracer \
  --tracer stack \
  --enable-memory-profiling \
  --allocation-threshold 1MB \
  --target-process "java"
```

---

## 🔧 Configuration Templates

### **Development Environment**
```yaml
# config/development.yaml
global:
  log_level: debug
  output_format: json
  
http_tracer:
  enable_correlation: true
  sampling_rate: 1.0
  max_payload_size: 1024
  
xdp_tracer:
  interfaces: ["lo"]
  sampling_rate: 1
  
stack_tracer:
  sampling_frequency: 49
  enable_user_stacks: true
  enable_kernel_stacks: false
```

### **Production Environment**
```yaml
# config/production.yaml
global:
  log_level: info
  output_format: json
  metrics_endpoint: ":9090/metrics"
  
http_tracer:
  enable_correlation: true
  sampling_rate: 0.1
  max_payload_size: 256
  enable_pii_filtering: true
  
xdp_tracer:
  interfaces: ["eth0", "eth1"]
  sampling_rate: 100
  flow_table_size: 65536
  
stack_tracer:
  sampling_frequency: 99
  enable_mixed_stacks: true
  max_stack_depth: 64
```

---

## 📈 Monitoring Dashboard Setup

### **Grafana Dashboard**
```bash
# Import pre-built dashboard
curl -o grafana-dashboard.json https://raw.githubusercontent.com/your-org/ebpf-tracing/main/dashboards/grafana.json

# Import to Grafana
curl -X POST \
  -H "Content-Type: application/json" \
  -d @grafana-dashboard.json \
  http://admin:admin@localhost:3000/api/dashboards/db
```

### **Prometheus Integration**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'ebpf-tracer'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 5s
    metrics_path: /metrics
```

---

## 🐛 Quick Troubleshooting

### **Permission Issues**
```bash
# If you get "Operation not permitted"
sudo ./build/universal-tracer

# Or set capabilities (preferred)
sudo setcap cap_sys_admin,cap_net_admin,cap_bpf+ep ./build/universal-tracer
```

### **eBPF Load Failures**
```bash
# Check kernel config
zgrep CONFIG_BPF /proc/config.gz

# Verify BTF support
ls /sys/kernel/btf/vmlinux

# Check program size
llvm-objdump -h *.o | grep -E "(text|maps)"
```

### **No Events Captured**
```bash
# Verify interface exists
ip link show

# Check if traffic is flowing
sudo tcpdump -i eth0 -c 10

# Increase verbosity
sudo ./build/universal-tracer --tracer http --log-level debug
```

### **High CPU Usage**
```bash
# Reduce sampling rates
--http-sampling-rate 0.01
--xdp-sampling-rate 1000  
--stack-sampling-frequency 19

# Use specific targeting
--target-process "nginx"
--target-container "web-app"
```

---

## 📚 Next Steps

1. **Read the Full Guide**: `docs/EBPF_TRACERS_GUIDE.md`
2. **Configure for Production**: `docs/CONFIG.md`
3. **Set Up Monitoring**: `docs/MONITORING.md`
4. **Performance Tuning**: `docs/PERFORMANCE.md`
5. **Security Hardening**: `docs/SECURITY.md`

---

## 🆘 Getting Help

- **Documentation**: `docs/`
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Community**: Slack/Discord
- **Support**: support@your-org.com

---

## ✅ Verification Checklist

- [ ] Kernel version 5.4+ verified
- [ ] All dependencies installed
- [ ] eBPF programs compiled successfully
- [ ] Basic test completed
- [ ] Configuration file created
- [ ] Monitoring dashboard set up
- [ ] Security considerations reviewed

**You're ready to start universal tracing!** 🎉
