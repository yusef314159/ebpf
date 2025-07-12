# Universal eBPF Tracer - Troubleshooting Guide

## 🔍 Quick Diagnostics

### **System Health Check**
```bash
# Run comprehensive system check
./universal-tracer --health-check

# Check eBPF support
./scripts/check-ebpf-support.sh

# Verify kernel configuration
./scripts/verify-kernel-config.sh

# Test compilation
make clean && make ebpf
```

### **Common Issues Checklist**
- [ ] Kernel version 5.4+ 
- [ ] Root privileges or proper capabilities
- [ ] eBPF support enabled in kernel
- [ ] Required packages installed
- [ ] Network interfaces exist
- [ ] Sufficient memory available
- [ ] No conflicting eBPF programs

---

## 🚨 Installation & Compilation Issues

### **Problem: Compilation Fails**

**Symptoms:**
```bash
clang: error: unknown target 'bpf'
make: *** [Makefile:35: http_tracer.o] Error 1
```

**Solutions:**
```bash
# Install/update clang and LLVM
sudo apt update
sudo apt install -y clang-12 llvm-12
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-12 100

# Verify clang supports BPF target
clang --print-targets | grep bpf

# Check LLVM version
llvm-config --version
```

### **Problem: Missing Headers**

**Symptoms:**
```bash
fatal error: 'linux/bpf.h' file not found
fatal error: 'bpf/bpf_helpers.h' file not found
```

**Solutions:**
```bash
# Install kernel headers
sudo apt install -y linux-headers-$(uname -r)

# Install libbpf development files
sudo apt install -y libbpf-dev

# Verify header locations
find /usr/include -name "bpf.h" 2>/dev/null
find /usr/include -name "bpf_helpers.h" 2>/dev/null
```

### **Problem: BTF Support Missing**

**Symptoms:**
```bash
libbpf: failed to find valid kernel BTF
libbpf: Error loading vmlinux BTF: -2
```

**Solutions:**
```bash
# Check BTF availability
ls -la /sys/kernel/btf/vmlinux

# Install BTF if missing (Ubuntu 20.04+)
sudo apt install -y linux-tools-$(uname -r)

# Generate BTF manually (if needed)
sudo pahole -J /boot/vmlinux-$(uname -r)
```

---

## 🔐 Permission & Security Issues

### **Problem: Permission Denied**

**Symptoms:**
```bash
bpf(BPF_PROG_LOAD): Operation not permitted
failed to load BPF program: Operation not permitted
```

**Solutions:**
```bash
# Run with sudo
sudo ./universal-tracer

# Set capabilities (preferred)
sudo setcap cap_sys_admin,cap_net_admin,cap_bpf+ep ./build/universal-tracer

# Check current capabilities
getcap ./build/universal-tracer

# Verify user permissions
id
groups
```

### **Problem: SELinux/AppArmor Blocking**

**Symptoms:**
```bash
audit: type=1400 audit(1234567890.123:456): avc: denied
AppArmor: DENIED operation="mount" profile="/usr/bin/tracer"
```

**Solutions:**
```bash
# Check SELinux status
sestatus
getenforce

# Temporarily disable SELinux (testing only)
sudo setenforce 0

# Create SELinux policy (production)
sudo setsebool -P domain_can_mmap_files 1

# Check AppArmor status
sudo aa-status

# Put profile in complain mode
sudo aa-complain /usr/bin/universal-tracer
```

### **Problem: Insufficient Memory**

**Symptoms:**
```bash
bpf(BPF_MAP_CREATE): Cannot allocate memory
failed to create BPF map: Cannot allocate memory
```

**Solutions:**
```bash
# Check memory usage
free -h
cat /proc/meminfo | grep -E "(MemTotal|MemAvailable)"

# Increase memory limits
echo 'vm.max_map_count = 262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Reduce map sizes in configuration
--flow-table-size 16384
--stack-map-size 4096
--ring-buffer-size 65536
```

---

## 🌐 Network & XDP Issues

### **Problem: XDP Attach Failed**

**Symptoms:**
```bash
failed to attach XDP program: Invalid argument
XDP attach failed on interface eth0
```

**Solutions:**
```bash
# Check interface exists
ip link show eth0

# Verify XDP support
ethtool -i eth0 | grep driver

# Use generic XDP mode
./universal-tracer --xdp-mode generic

# Check for conflicting XDP programs
sudo bpftool net list

# Detach existing XDP programs
sudo ip link set dev eth0 xdp off
```

### **Problem: No Network Events**

**Symptoms:**
```bash
XDP tracer started but no events captured
Network interface shows no traffic
```

**Solutions:**
```bash
# Verify traffic on interface
sudo tcpdump -i eth0 -c 10

# Check interface statistics
cat /proc/net/dev | grep eth0

# Test with loopback interface
./universal-tracer --tracer xdp --interface lo

# Generate test traffic
curl http://httpbin.org/get
ping -c 5 google.com

# Check XDP program attachment
sudo bpftool net list dev eth0
```

### **Problem: High Packet Loss**

**Symptoms:**
```bash
XDP: high packet drop rate
Network performance degraded
```

**Solutions:**
```bash
# Increase ring buffer size
--ring-buffer-size 1048576

# Adjust sampling rate
--xdp-sampling-rate 100

# Use multiple RX queues
sudo ethtool -L eth0 combined 4

# Check CPU affinity
sudo irqbalance --oneshot

# Monitor XDP statistics
sudo bpftool prog show | grep xdp
```

---

## 📊 HTTP Tracing Issues

### **Problem: No HTTP Events Captured**

**Symptoms:**
```bash
HTTP tracer running but no events
Syscalls hooked but no HTTP detected
```

**Solutions:**
```bash
# Verify HTTP traffic exists
sudo netstat -tlnp | grep :80
sudo ss -tlnp | grep :8080

# Test with simple HTTP server
python3 -m http.server 8000 &
curl http://localhost:8000/

# Check syscall hooking
sudo bpftool prog list | grep tracepoint

# Enable debug logging
./universal-tracer --log-level debug --tracer http

# Verify process targeting
./universal-tracer --target-process nginx --tracer http
```

### **Problem: Incomplete HTTP Parsing**

**Symptoms:**
```bash
HTTP events missing method/path
Partial HTTP headers captured
```

**Solutions:**
```bash
# Increase payload capture size
--max-payload-size 4096

# Check for HTTP/2 or gRPC traffic
./universal-tracer --enable-grpc --tracer http

# Verify SSL/TLS termination
sudo netstat -tlnp | grep :443

# Test with plain HTTP
curl -v http://localhost:8080/test
```

### **Problem: High HTTP Event Rate**

**Symptoms:**
```bash
Too many HTTP events generated
System performance impact
```

**Solutions:**
```bash
# Reduce sampling rate
--http-sampling-rate 0.1

# Add path filtering
--exclude-paths "/health,/metrics,/favicon.ico"

# Limit event rate
--max-events-per-second 1000

# Use burst limiting
--burst-limit 100
```

---

## 🔍 Stack Tracing Issues

### **Problem: No Stack Traces Captured**

**Symptoms:**
```bash
Stack tracer running but no samples
Profiling enabled but no flame graph data
```

**Solutions:**
```bash
# Verify target processes exist
ps aux | grep nginx
pgrep python3

# Check sampling frequency
./universal-tracer --sampling-frequency 99 --tracer stack

# Enable kernel stacks
./universal-tracer --enable-kernel-stacks --tracer stack

# Test with specific PID
./universal-tracer --pid 1234 --tracer stack

# Check perf event support
sudo perf record -g -p 1234 sleep 1
```

### **Problem: Symbol Resolution Failed**

**Symptoms:**
```bash
Stack traces show only addresses
No function names in flame graph
```

**Solutions:**
```bash
# Install debug symbols
sudo apt install -y libc6-dbg
sudo debuginfo-install glibc

# Verify symbol files
objdump -t /usr/bin/nginx | head
nm /usr/bin/python3 | head

# Check DWARF information
objdump -W /usr/bin/myapp | head

# Add symbol paths
--symbol-paths "/usr/lib/debug:/proc/kallsyms"

# Enable frame pointers
./universal-tracer --enable-frame-pointers --tracer stack
```

### **Problem: Stack Unwinding Errors**

**Symptoms:**
```bash
Incomplete stack traces
Stack unwinding failed errors
```

**Solutions:**
```bash
# Reduce stack depth
--max-stack-depth 32

# Use frame pointers instead of DWARF
--enable-frame-pointers --disable-dwarf

# Check for stripped binaries
file /usr/bin/myapp
objdump -h /usr/bin/myapp | grep debug

# Compile with frame pointers
gcc -fno-omit-frame-pointer -g myapp.c
```

---

## 📈 Performance Issues

### **Problem: High CPU Usage**

**Symptoms:**
```bash
eBPF tracer consuming high CPU
System performance degraded
```

**Solutions:**
```bash
# Reduce sampling rates
--http-sampling-rate 0.01
--xdp-sampling-rate 1000
--stack-sampling-frequency 19

# Increase batch sizes
--batch-size 1000

# Use CPU affinity
taskset -c 0,1 ./universal-tracer

# Monitor CPU usage
top -p $(pgrep universal-tracer)
perf top -p $(pgrep universal-tracer)
```

### **Problem: High Memory Usage**

**Symptoms:**
```bash
Memory usage continuously growing
Out of memory errors
```

**Solutions:**
```bash
# Reduce map sizes
--flow-table-size 16384
--connection-table-size 1000
--stack-map-size 4096

# Enable memory limits
systemd-run --scope -p MemoryLimit=1G ./universal-tracer

# Monitor memory usage
cat /proc/$(pgrep universal-tracer)/status | grep -E "(VmRSS|VmSize)"

# Check for memory leaks
valgrind --leak-check=full ./universal-tracer
```

### **Problem: Event Loss**

**Symptoms:**
```bash
Ring buffer full warnings
Events being dropped
```

**Solutions:**
```bash
# Increase ring buffer size
--ring-buffer-size 1048576

# Increase processing threads
--worker-threads 8

# Reduce event generation
--sampling-rate 0.1

# Monitor ring buffer usage
sudo bpftool map dump name ring_buffer
```

---

## 🔧 Advanced Debugging

### **eBPF Program Debugging**
```bash
# List loaded programs
sudo bpftool prog list

# Show program details
sudo bpftool prog show id 123

# Dump program instructions
sudo bpftool prog dump xlated id 123

# Check program logs
sudo bpftool prog tracelog

# Verify map contents
sudo bpftool map dump name flow_table
```

### **Kernel Tracing**
```bash
# Enable eBPF tracing
echo 1 | sudo tee /sys/kernel/debug/tracing/events/bpf/enable

# Monitor eBPF events
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep bpf

# Check kernel logs
sudo dmesg | grep -i bpf
sudo journalctl -k | grep -i bpf
```

### **Network Debugging**
```bash
# Monitor network interfaces
sudo iftop -i eth0
sudo nethogs

# Check packet drops
cat /proc/net/dev | grep eth0
ethtool -S eth0 | grep drop

# Analyze traffic patterns
sudo tcpdump -i eth0 -w capture.pcap
wireshark capture.pcap
```

---

## 📞 Getting Help

### **Diagnostic Information to Collect**
```bash
# System information
uname -a
cat /etc/os-release
lscpu
free -h

# Kernel configuration
zgrep CONFIG_BPF /proc/config.gz
ls -la /sys/kernel/btf/

# eBPF tools versions
clang --version
llvm-config --version
bpftool version

# Network configuration
ip addr show
ip route show
```

### **Log Collection**
```bash
# Enable debug logging
./universal-tracer --log-level debug --log-file debug.log

# Collect system logs
sudo journalctl -u universal-tracer > service.log
sudo dmesg > kernel.log

# eBPF program information
sudo bpftool prog list > bpf-progs.txt
sudo bpftool map list > bpf-maps.txt
```

### **Support Channels**
- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Check `docs/` directory
- **Community Forum**: Ask questions and share solutions
- **Professional Support**: Contact support team

---

## ✅ Prevention Best Practices

1. **Regular Updates**: Keep kernel and tools updated
2. **Resource Monitoring**: Monitor CPU, memory, and network usage
3. **Configuration Validation**: Test configurations before deployment
4. **Gradual Rollout**: Start with low sampling rates in production
5. **Backup Plans**: Have rollback procedures ready
6. **Documentation**: Keep deployment notes and configurations

This troubleshooting guide covers the most common issues and their solutions. For complex problems, enable debug logging and collect diagnostic information before seeking help.
