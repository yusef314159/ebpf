Introduction
This project involves the implementation of a scalable and universal software
package for the dynamic collection of call stacks, their arguments and detailed
analysis of function latency using the capabilities of eBPF.
The main goal is to provide cross-language and cross-platform monitoring
without the need to directly make changes to the source code of applications and
services. The project is focused on working in production environments with a high
level of security and performance requirements. Particular attention is paid to the
support of multi-level tracing, covering the interaction between the Linux kernel and
the userspace, as well as integration with distributed systems and container
infrastructure. The methodological basis of the solution is based on the use of BTF
and DWARF for detailed recovery of symbolic information, which is critical for
obtaining representative stacks, especially in environments with disabled debug
symbols. The technology stack includes the use of uprobes and kprobes for flexible
interception of events at key points in code execution.
It is planned to introduce advanced mechanisms for correlating HTTP/gRPC
requests with automatic extraction and substitution of Trace ID in the data stream,
which will allow combining disparate call chains into a single picture of distributed
tracing. Considerable attention will be paid to the implementation of optimized
kernel-level sampling and filtering to reduce overhead and minimize the impact on
the target system. Ultimately, the product should cover the tasks of in-depth
performance profiling, providing reference data for detailed security audits, anomaly
detection, and optimization of critically loaded services in modern heterogeneous
infrastructures.
2. Review of existing solutions and their limitations
Modern tracing tools built on eBPF demonstrate significant progress in the
field of dynamic analysis of application behavior and the Linux kernel. However, a
detailed analysis reveals a number of technological and organizational limitations,
which are especially evident when scaling such tools to high-load distributed
architectures and multi-language environments with different types of runtimes.
2.1 BCC and bpftrace platforms
BCC (BPF Compiler Collection) offers a powerful stack of libraries and
utilities that allow you to quickly develop and deploy trace scripts. At the same time,
reliance on the full Clang/LLVM chain on the target nodes requires additional
infrastructure maintenance, complicates portability, and raises security questions
about automated builds. For large CI/CD pipelines, this means taking into account
compiler versions, kernel headers, and debugging information. bpftrace is positioned
as a convenient tool for express diagnostics and one-time scenarios, but its DSL-
oriented approach does not translate well to complex distributed scenarios with deep
call nesting. As the number of samples increases, the load on the core can increase
exponentially, and the lack of full-fledged data reuse mechanisms leads to
fragmentation of monitoring logic.
2.2 Perf, SystemTap и strace
Perf and SystemTap remain popular among system engineers due to their
historical reliability and predictability. However, their use for observability in cloud
or containerized environments faces obstacles: the need to compile additional kernel
modules and the inability to dynamically manage probes in runtime contradict
modern DevOps approaches. strace is useful for spot debugging, but its system call
trace method is blocking and unsuitable for permanent use in production, as it
introduces a serious overhead and breaks multithreaded applications.
2.3 OpenTelemetry-eBPF (Grafana Beyla, Pixie)
Next-generation solutions such as Beyla and Pixie demonstrate the ability to
integrate eBPF capabilities into the full OpenTelemetry ecosystem. They can
automatically extract distributed trace contexts and associate them with
HTTP/gRPC traffic. However, their operating models require advanced kernel and
container privileges, making them difficult to operate with a tight security policy
and Secure Boot activated. Contextual correlation is often implemented through
heuristic parsing of network tuples, which does not guarantee reliability for
asynchronous calls and multiple packet relays.
2.4 Internal limitations of eBPF
The key feature of eBPF — a strict model for verifying programs in the kernel
— remains both a strength and a technical barrier. The developer needs to constantly
balance between the expressiveness of the trace logic and the limits of the stack
depth, the size of the BPF cards and the number of tail-call transitions. The use of
BTF or DWARF becomes critical for the correct parsing of structures, but in real
production systems, debugging information is often missing for security or
optimization reasons. When working with dynamic and just-in-time languages such
as Python or JavaScript, a traditional eBPF without runtime injections cannot extract
the full function names and argument values, which requires a combination with
LD_PRELOAD, Frida, or specialized bytecode-level tracing agents.
3. Requirements
3.1 Functional requirements
MVP:
Function entry/exit tracing. The tool should provide the most flexible configuration
of trace injection points using the kprobe and uprobe mechanisms, which involves
filtering events by process name, PID, namespace, and full path to the binary. This
granularity minimizes overhead and avoids collisions when working in multi-
container environments and complex process hierarchies.
Collect function arguments. For each traced point, arguments of primitive types,
pointers, and, if necessary, basic data structures are retrieved using safe eBPF helpers
bpf_probe_read() and additional integrity checks. This will allow you to build a
complete picture of the call context in multithreaded execution.
Accurate latency measurement. All entry and exit events should be timestamped with
high accuracy via bpf_ktime_get_ns(), with intermediate values stored in BPF maps
for later matching. In addition, it is necessary to provide the ability to calculate
latency in the context of individual processes, goroutines, or threads in order to
eliminate distortion during parallel traces.
Reliable data transfer to userspace. Data transfer should use a ring buffer or perf
buffer, with the use of ring buffer (starting with kernel 5.8) taking precedence due to
high bandwidth and minimal copies. It is important to provide a backpressure
mechanism to avoid event losses during peak loads.
Reconstruction of call stacks. The basic strategy should be to parse through frame
pointers from fallback to DWARF-unwinding for cases where FP is not available. It
is necessary to ensure correct work with binaries built without the save frame pointers
flag, and to flexibly switch between stack unpacking methods.
Additionally:
Automatic correlation of HTTP/gRPC requests. The correlation engine must
automatically extract trace-id from incoming HTTP headers or gRPC metadata and
inject them into outbound requests. This is critical for the end-to-end construction of
distributed transaction chains.
Handle asynchronous calls and execution context. You want to support tracing
context transfers between threads and asynchronous entities (goroutines) while
maintaining the relationship between events even when dynamically rebalancing.
Advanced filtering and dynamic sampling. The functionality should include the
ability to filter events by URL, gRPC methods, PID, as well as flexible configuration
of sampling at the kernel level (via timers or conditional kprobe). This will allow you
to adapt the intensity of data collection to the current load of the system.
Flexible and extensible export formats. It is necessary to provide support for multiple
export formats (JSON, protobuf, OpenTelemetry Trace) and ensure compatibility
with various observability systems, such as Jaeger, Prometheus, Grafana Tempo.
3.2 Non-functional requirements
MVP:
Minimize overhead costs and optimize performance. All eBPF code should be
designed with strict verifier constraints in mind: a minimum call stack, avoiding
potentially infinite loops, and using tail-calls to simplify the call graph. In addition, a
resource intensity analysis is required for different load patterns.
Performance security and access control. All system components must use only core-
approved eBPF helpers and operate through secure channels of interaction with user
space. Telemetry must be encrypted and authenticated between the agent and external
services.
Modularity and scalability of the architecture. It is important that the tracer core and
userspace agent are fully isolated and easily scalable modules. This will simplify the
update and allow them to be flexibly integrated into existing DevSecOps pipelines.
Additionally:
Support for CI/CD processes and infrastructure testing. Automatic build of eBPF
programs for different kernel versions should be implemented using containerization,
QEMU or cloud test environments for BTF/DWARF verification. Integration into
existing CI/CD pipelines with full tests and coverage reports is preferred.
Advanced monitoring and flexible logging. The system should keep a detailed log of
all stages of execution and register key metrics: the number of successfully processed
events, verification failures, dropped events, delays in transmission chains. These
metrics should be exported to the monitoring system.
Complete documentation and ready-made examples. The platform should come with
comprehensive guides, ready-made configurations and templates for deployment to
Kubernetes, Helm charts, examples of CI pipelines, and integrations with popular
observability tools.
4. Architectural description
This section provides a detailed structure and interconnection of the
subsystems that make up the holistic architecture of a generic eBPF tracer, with a
focus on industry-level requirements and exploratory aspects of implementation.
4.1 Core: eBPF programs
The kernel is a set of pre-compiled eBPF bytecodes prepared with CO-RE and
BTF metadata for maximum portability between kernel versions. Each program
undergoes strict verification and connects to relevant trace points: kprobe, fentry,
fexit to monitor kernel functions; uprobe — for user space; tracepoint, XDP, and tc
are used to process network packets. To organize efficient data exchange between
contexts, the BPF maps system is used: ring buffer or perf buffer ensure the delivery
of events with minimal latency and overhead. The kernel can use hash maps and
counter tables for aggregation, and tail-call chains allow you to dynamically expand
the call graph without exceeding stack depth limits.
4.2 Userspace Agent
The agent functions as a privileged or non-privileged daemon that initializes
eBPF programs via libbpf or BCC, opens the appropriate maps, and processes the
event stream. Each event is deserialized with critical attributes highlighted: process
ID, timestamps, function arguments, and the reconstructed call stack. Next, the
TraceContext correlation mechanism is implemented, which ensures data
connectivity during distributed tracing of HTTP/gRPC requests or asynchronous
operations. The agent aggregates data, applies a sampling strategy, and routes the
information flow depending on the selected protocol (gRPC, HTTP, message queue,
or file log). To ensure resiliency, backpressure logic and bit rate limits are provided,
accompanied by logging of unsuccessful attempts and dropped event metrics.
4.3 Communication subsystems
The communication component is responsible for integrating the collected
telemetry data into external systems. Export can be implemented via gRPC/HTTP
with support for OTLP/Jaeger formats or through message brokers (Kafka, NATS)
to build scalable data pipelines. For debugging purposes, it is possible to upload to
the file system or stream logs. Flexibility is provided by support for various
configuration channels: CLI, YAML/JSON, environment variables. Kubernetes has
Helm charts and operators that make it easy to deploy and automate updates. An
important part of the communication architecture is the inclusion of CI/CD pipelines
with virtual core testing (QEMU), including BTF compatibility and CO-RE
validation.
4.4 Configuration
The configuration layer provides support for static and dynamic tracing
patterns. Filtering, sampling, argument extraction, and context correlation rules are
described in YAML/JSON format with the ability to hot-refresh via APIs or
command flags without the need to restart the agent. This flexibility is important for
production environments with variable workloads and changing monitoring
requirements.
4.5 Architectural integrity
Architectural separation emphasizes safety and sustainability. The kernel
requires superuser privileges only for the initial bootstrap of eBPF programs, after
which the agent can function with minimal privileges. Using CO-RE minimizes
assembly fragmentation for different kernel versions. The modular nature of the
solution follows the principles of DevSecOps: components can be configured and
updated independently, without interrupting the overall data collection chain.
4.6 Schematic representation
5. Technical Implementation: Kernel and User Agent
5.1 Downloading and verifying eBPFs
Source code development is carried out in C with mandatory optimization for
CO-RE and BTF metadata. This guarantees portability without recompilation to
different Linux kernels and reduces the risk of incompatibility. The kernel verifier
analyzes the entire control thread, excludes non-deterministic loops, verifies the
correctness of memory accesses, and checks strict stack depth limits (≤512 bytes).
For complex scenarios, it is possible to use bytecode pre-simulations using test
frameworks to reduce the likelihood of a load failure at the production node.
5.2 Hook Selection Strategy
A reference practice is the layered use of kprobe, fentry, and fexit to track
kernel system calls and key points in drivers. In the user space, uprobe and USDT
(User-Level Statically Defined Tracing) are actively used, which gives flexibility
for dynamically loaded libraries and interpreted languages. To extend the accuracy
of profiling, combined points are used: function input/output, as well as tracepoints
and cgroup-based filtering.
5.3 Data collection and communication mechanism
Data committing begins with retrieving a timestamp via bpf_ktime_get_ns(),
after which PIDs, TIDs, function arguments, and, if necessary, additional context
tokens are stored. Pointer readings through bpf_probe_read() are performed with
validity checks to prevent the program from crashing. Event structures are written
to the BPF map with unique keys based on the PID or stack hash. To pass to
userspace, perf buffer or ring buffer are used (with priority on ring buffer for kernels
>=5.8). This guarantees stable throughput, latency reduction, and backpressure
control to avoid data loss during peak loads.
5.4 Call stack reconstruction
In scenarios with frame pointers, bpf_get_stack() is used, which gives an
inexpensive and fast snapshot of the current stack. If FP is missing, DWARF-based
unwinding is activated: .eh_frame tables are extracted in advance, which are
analyzed by the agent or inside the eBPF. Polarsignals practice proves that this
approach works if symbolization is reliably maintained. In the case of a kernel build
with BTF (CONFIG_DEBUG_INFO_BTF), automatic type generation is available,
making it easier to access complex kernel structures without the need for manual
header parsing.
5.5 User Agent Logic
The userspace agent initializes the eBPF load via libbpf or BCC, deploys
hooks and BPF maps, and listens to the ring buffer or perf buffer. Event
deserialization includes parsing PIDs, TIDs, arguments, timestamps, and stacks. The
collected data is aggregated and formed into span chains with TraceContext support,
which is important for distributed tracing. The agent adjusts the sampling rate and
dynamically applies filters to reduce the overhead. Export is implemented via OTLP,
Jaeger, Kafka or Prometheus, with backup logs in case of failures. An important
element is the collection and exposure of CPU usage metrics, dropped events, and
verification errors.
5.6 Case Study: Parca
Parca demonstrates efficient sampling profiling at ~19 Hz, supporting CO-RE
and BTF compatibility. Stack snapshots are written to two BPF maps (stack ID and
frequency counters), after which the user agent symbolizes, exports the data to the
pprof format, and passes it to the backend. For production environments, a Helm
chart for Kubernetes and a CI/CD pipeline with QEMU have been implemented to
emulate different cores and check the stability of CO-RE. Support for backpressure
and sampling control minimizes event losses during peak loads.
6. Correlation of HTTP/gRPC requests and asynchronous calls
6.1 Automated transfer and implementation of TraceContext at the transport
layer
Within the framework of the modern distributed tracing paradigm, eBPF
agents provide a unique opportunity for transparent, invisible to the application
layer, extraction and subsequent injection of the TraceContext at the transport layer.
In practice, this is implemented through an in-depth analysis of network protocol
headers (HTTP/1.x, HTTP/2, gRPC), which are standardized in the W3C Trace
Context format. The algorithm includes dynamic interception of incoming network
events: the eBPF program decodes the traceparent field associated with the incoming
request. If the identifier is missing, a new unique trace-id is initiated, which ensures
the continuity of trace chains even in the absence of upstream integration. If trace-
id is present, it is taken as the main key for building all further logic of propagation
and inheritance of the context in all outgoing calls, as well as for the subsequent
analysis of cause-and-effect relationships between services.
Trace-id injection into outbound HTTP/gRPC transactions is possible thanks
to kernel eBPF helpers (e.g., bpf_probe_write_user), which fundamentally expands
the use of agentlesstracking and guarantees complete coverage regardless of the
source language of the application or framework. However, the architectural
elegance of this approach is complicated by the strict security measures of modern
Linux kernels: starting with version 5.14, when Secure Boot is enabled or kernel
lockdown mode is active, write helpers can be severely restricted or blocked at the
kernel policy level, which leads to the need to design fallback mechanisms or manual
TraceContext integrations for critical production-grade scenarios. The difficulty lies
not only in the technical impossibility of injection, but also in the legal and
operational restrictions of operating such solutions on corporate and cloud
platforms.
6.2 Semantics of asynchronous executions and interthreaded correlation
Passing trace context under conditions of intense asynchrony—for example,
mass generation of goroutines in Go, threads and fiber objects in the JVM, and
asynchronous coroutines in Python—requires semantically rigorous strategies for
tracking parent and child execution contexts. To do this, progressive eBPF agents
such as Grafana Beyla integrate directly with runtime system structures, capture
each spawn transition (the creation of a new asynchronous entity), and form cross-
threaded relationships for trace-id between parent and child execution contexts.
As a result, automated, transparent for the application code, TraceContext
propagation is achieved even in conditions of deep nesting of parallel tasks,
including the generation of temporary auxiliary identifiers for tasks with an
undefined or dynamically changing hierarchy. For JVM or Python, introspection of
internal identifiers of async/greenlet structures is possible, which in modern versions
of eBPF expands the range of agentless -applicabilitytressing and allows you to build
universal correlation mechanisms in the most complex scenarios of competitive
execution. This significantly increases the granularity of trace chain analysis and
minimizes invisibility when profiling high-load systems.
6.3 Black-box correlation and spatial referencing by network tuples
In cases where the application does not implement direct integration with
OpenTelemetry or does not support header injection, a black-box correlation
strategy is used. The principle is based on associating trace-id with the unique
characteristics of a network connection formed by a five-tube connection (source IP,
source port, dest IP, dest port, protocol). eBPF allows real-time storage of trace-id
associations <-> a connection in BPF maps directly in the kernel space, where each
new TCP/UDP stream defined by the 5-tuple becomes a context carrier. The entire
chain of events within a single connection is automatically tagged with the
appropriate trace-id, which allows post-factum reconstruction of distributed tracing
even without application layer support.
However, this approach is architecturally limited: it works only within the
boundaries of a single host (node-local), since the BPF map is a kernel space object
of a particular machine. In conditions of high connection dynamics (for example,
hundreds of thousands of short-lived TCP streams in high-load systems), there is a
risk of depletion of available slots in the BPF map, which requires the design of TTL
(time-to-live) strategies and periodic garbage collection to prevent kernel
degradation. In addition, system limits on the size of the BPF map and the number
of open file descriptors can become a critical factor in production clusters, so
monitoring the kernel dataplane and automated scaling of BPF stores become a
mandatory part of the operational cycle.
6.4 Complex gRPC correlation example: Pixie and Groundcover cases
Empirical research and practice of the Pixie and groundcover projects show
that the most complete correlation between gRPC and other RPC protocols is
achieved by combining the capabilities of kernel space and userspace. Kernel-side
kprobe and tracepoint tools collect low-level network stack events, intercept TCP
sessions, parse the HTTP-layer, and detect when connections are established and
terminated. In turn, userspace injections use uprobe to analyze the internal memory
structures of popular gRPC libraries, extracting trace-id, method names, metadata,
call parameters, as well as dynamic application attributes that are not visible at the
kernel level.
Such a dual approach allows you to build detailed, universal trace chains
regardless of the source language of the application (Go, C++, Java, Python, etc.) or
the architecture of the service. The hybridity of the method minimizes the probability
of false positive correlations, as well as increases the accuracy and depth of the
analysis of distributed scenarios. In practice, this becomes key for high-load
microservice environments, where most of the communications take place through
intermediate proxies, service mesh architectures, and non-standard RPC solutions.
7. Sampling, filtering, and optimization (limitations of eBPF and best
practices)
7.1 Kernel-level predictive filtering
Current engineering practices for building fault-tolerant and scalable eBPF
tracers unequivocally assume the priority of the earliest, multi-level filtering of
events. Implementing predictive filtering directly in eBPFs before moving to
userspace not only minimizes the overhead of scheduling, synchronizing, and
processing events, but also significantly reduces the parasitic load on the CPU, the
layer of context switching, and I/O traffic between the core and the user space. A
well-implemented filter can reduce the amount of data transmitted by several times,
leaving only events relevant to monitoring and security purposes in the stream.
Filtering by PID/Process Name: Implemented by calling bpf_get_current_pid_tgid(),
directly comparing with allow-list/deny-list values, and parsing the process's
character identifiers (e.g., through saved userspace mapping in the BPF map). In high-
load systems, bloom filters can be used, minimizing the cost of lookup.
Namespace and UID: For selective monitoring of containers, services, and isolators,
the contents of structures received through current->nsproxy and
bpf_get_current_uid_gid() are analyzed, with the ability to combine filtering by
multiple namespaces and user ID.
Filtering by network attributes: In network use-cases, precise filtering is possible by
port, IP, tuple (e.g. sk->skc_dport), by proto, as well as by parsing gRPC/HTTP
metadata inside uprobes, tracepoints, and dynamic trace-events. Complex scenarios
can involve packet-level pattern matching, which integrates with the
sockmap/sockhash and XDP BPFs.
Modern research (Datadog, Tigera, Unibo) and operational reports prove that
competent multi-level filtering reduces the flow of processed events by orders of
magnitude without loss in the completeness of observation, which is critically
important for distributed microservice landscapes.
7.2 Sampling: Methods for Reducing Load and Managing Data Volume
To contain the load on the kernel and userspace agents in conditions of
extreme frequency of events, compositional sampling strategies are implemented:
Systematic Sampling: The use of global and/or per-CPU counters or atomic BPF
maps (BPF_MAP_TYPE_PERCPU_ARRAY) to allow processing of only every Nth
event. In large scenarios, an adaptive scheme (dynamically changing N based on the
current load) is acceptable.
Latency-triggered Sampling: Latency-triggered profiling - Events are captured and
sent only when the user-defined threshold is exceeded by the execution time. This
approach allows you to focus on anomalies, outliers, and SLO violations. Often
combined with latency and per-function metrics.
Timer snapshooters and statistical profiling: Regular profiling (e.g., every
perf_event) at fixed or dynamic intervals implements balanced call stack coverage
for further aggregation (flame graph, pprof, folded stack traces, etc.).
Dynamic Trace Enable/Disable: Use the BPF map or eBPF configuration API to mark
active PIDs, trace-enabled/disabled filters in runtime. This allows you to quickly
scale agents by activating tracing only on selected objects without downtime, which
is especially valuable for large infrastructures and CI/CD pipelines.
The comprehensive use of these techniques makes it possible to implement
trigger audits with precise detail, as well as to organize highly efficient sampling
with the possibility of further streaming analytics (for example, building histograms
of delays or automatic detection of anomalies in real time).
7.3 Principles of eBPF code optimization
eBPF programs are severely limited both in terms of execution resources and
the requirements of the Linux kernel verifier. This requires strict adherence to best
engineering practices and constant monitoring of the performance profile:
Tail-calls and modularity: Decomposition of complex tracing tasks into minimal
eBPF programs with control transfer through tail_call
(BPF_MAP_TYPE_PROG_ARRAY). This partitioning allows you to reduce the
stack depth, distribute logic between programs, emulate dynamic DAGs/handler
graphs, and bypass verifier limits.
Minimize kernel logic: All calculations that require aggregation, sorting, complex
logic, or large amounts of data should be outsourced to userspace whenever possible.
In eBPF, only the collection of a minimum amount of data and the simplest
preprocessing (e.g. filtering and time recording) are allowed.
Using BPF maps instead of an eBPF stack: Any intermediate or aggregating structure
is placed in a BPF hash map, LRU map, array map, etc., which gives storage
flexibility, thread-safety, and transparent cleanup. The use of the stack is strictly
limited (up to 512 bytes), and exceeding the limit leads to the non-admission of the
program to the kernel.
Strict avoidance of non-deterministic loops and unstable execution paths: All loops
must be statically unrolled; Depth and branches are computed at compile. The use of
recursion, dynamic memory allocation, and arbitrary jumps is strictly prohibited.
Similarly, any operations with an indefinite number of iterations are prohibited,
which is controlled by the static analysis of the verifier.
JIT and compatibility: If you have JIT compiler support, you should use it to speed
up your code, but the architecture should provide fallback mechanisms for non-JIT
kernels (or with JIT disabled for security reasons).
Strict encapsulation of logic: In the production environment, it is recommended to
create versions of eBPF programs with strictly separated areas of responsibility:
collection, filtering, minimal preprocessing — strictly in the core, all analytics,
aggregation, and export — in userspace. This scheme makes it easier to maintain,
upgrade, and reduces the risk of kernel upgrade failures.
Operational practices (e.g., in Groundcover, Parca) prove that inefficiently
optimized eBPF programs under production load conditions can lead to a sharp
increase in CPU, increased latency, and violation of SLO, leveling the main
advantages of eBPF technologies.
7.4 Kernel limitations and compatibility requirements
The Linux kernel verifier is a formally verifiable state machine that provides
strict guaranteed correctness, completeness, and security of each eBPF program
loaded into the kernel:
Guaranteed completion: Any branch of execution, including error handling and
conditional branching, must be completed in no later than a predefined number of
steps. Programs with potentially infinite loops or an excessive number of branches
will be rejected at boot time.
Stack depth limit: Regular eBPF programs are limited to a stack of 512 bytes, while
tail-calls chains are limited to 256 bytes. Exceeding the limit instantly blocks the
download; This requires careful analysis of the structure and size of all local variables
and buffers.
Availability of eBPF helpers: Use only authorized helpers - any access to memory,
registers or system structures is controlled by the kernel; Access violations or
incorrect work with pointers (for example, user pointer dereference without checking)
lead to a failed loading.
Kernel resource limits: The number of simultaneously active BPF maps, the size of
each map, the number of counters and other structures are strictly limited by kernel
parameters (sysctl, boot parameters, etc.) and must be monitored by the userspace
agent to prevent the limits from being exhausted (memory leak, map overflows).
Secure Boot/Kernel Lockdown: In high-security modes (Secure Boot, Lockdown),
some eBPF helpers become unavailable (e.g., the bpf_probe_write_user used to inject
the TraceContext), which limits the monitoring functionality and requires fallback.
Detection of kernel capabilities: Before loading any program (especially with CI/CD
and deploying to different hosts), bpftool feature or similar utilities must be called to
check the support of all the necessary kernel functions: the presence of ringbuf,
tail_call, RW maps, JIT, kfunc and other extensions. Without such a check,
degradation or complete failure of the tracer is possible.
JIT/Interpretation fallback: In the absence of JIT compilation, the eBPF code is
executed by the kernel interpreter, which is much slower and requires separate
performance profiling in production.
Failure to meet any of the above criteria will result in an immediate failure to
download the program, errors in operation, or uncontrolled degradation during
operation in combat conditions.
7.5 Recommendations for CI/CD, Operations and Verification
Practice Description
Strict separation of
logic
All business logic and aggregation - userspace; Core - only event collection, minimal
preprocessing, filtering
Multi-core CI and
integration tests
Use bpftool verify, QEMU emulation, and a test matrix on different kernel versions
to test all target features and limit platform compatibility bugs
Practice Description
Deep runtime
monitoring

Embed reporting on drop rate, map-usage, event latency, integration with
Prometheus, Grafana, Loki for end-to-end monitoring of production health
Fallback & Flexible
Shipping

Provide alternative binary BPF options (e.g., fallback without tail_call/ringbuf) to
support legacy kernels and automatic switching to the CI/CD-pipeline
Advanced examples
and templates

Prepare code-snippets of filtering, sampling, map-init, autotests for typical cases and
scenarios; publish troubleshooting guides and step-by-step manuals for developers
and SREs
Example: Integrating filtering and sampling into eBPF
In this example, multi-level filtering (by PID) is implemented, as well as N-
th event sampling, which makes it possible to adapt such patterns to the specifics of
each production task. For complex cases, the template can be extended by filtering
by ports, gRPC methods, namespace, as well as dynamic activation by external flag
(via BPF map).
8. Instructions for Starting and CI/CD Process
8.1 Building eBPFs
Building and integrating eBPFs requires formalizing an extensive, multi-
layered pipeline focused on portability, validation, and interoperability across
multiple versions of the Linux kernel. At the stage of preparing a CI/CD pipeline, it
is necessary to provide:
Automated installation of all necessary dependencies: Clang/LLVM (version 13 or
higher, for CO-RE and BTF support), libbpf, bpftool, as well as linux-headers
corresponding to both the current CI runner kernel and target kernels (legacy and
production);
vmlinux pre-collection and aggregation procedures with full BTF information.
Generating vmlinux.h via bpftool btf dump file... > vmlinux.h is becoming a
mandatory practice to support BTF-aware and CO-RE eBPF programs;
Checking the synchronization of header files, BTFs, and collected binaries through
automated smoke tests and sanity checks to ensure compatibility between eBPF
objects and kernels with different configurations;
Replication of the build process in environments with different kernel versions
through the launch of virtual machines (QEMU/KVM), containers (Docker-in-
Docker) and emulators, with fixation of artifacts at each stage for reproducibility of
research and deployment;
Implementation examples: a deployed CI pipeline consists of code linting (clang-
tidy), compiling C-sources, generating CO-RE bytecode, integration testing using
bpftool (bpftool prog load, bpftool prog test run), as well as checks in production-like
VM/containers with the ability to integrate Linux kernel selftest cases.
8.2 Running eBPF Programs and Userspace Agent
Deploying and launching an eBPF infrastructure in a production environment
requires the construction of detailed loading scenarios, program lifecycle
management and BPF maps, as well as automated status monitoring:
The standard loading procedure involves using bpftool prog load to mount eBPF
programs and automatically pinning maps and programs in BPFFS. This ensures
stateful behavior between service restarts and simplifies upgrade/rollback — for
example, through pinned maps migration;
The userspace agent is implemented in the form of a systemd unit or an autonomous
daemon (Go, C, Python), which provides loading of eBPF programs, detection and
initialization of the necessary maps, status monitoring and automatic recovery from
errors (restart on-failure);
An important stage of initialization is the validation of vmlinux/BTF availability,
correctness of rights, readiness of all paths (BPFFS, maps). Centralized aggregation
of BTF and supporting files facilitates updates and rollbacks;
Automation of rights configuration is possible: support for both root launch and
unprivileged eBPF modes, provided that the kernel supports it correctly, with
dynamic validation (bpftool feature probe);
For Kubernetes, it is possible to integrate agents with Helm charts, support for hot-
reload and zero-downtime migrations, and automated updates via Operator.
8.3 CI/CD: Advanced Verification, Testing, and Analysis Steps
The CI/CD pipeline for eBPF projects is built around sequential phases of
verification and quality control:
Stage Description
Unit tests
For the userspace agent, there are standard frameworks (Go test, pytest); for eBPF, it is the
automation of selftest using BPF_PROG_TEST_RUN, or the launch of custom BPF
programs in sandbox environments.
Lint и static
analysis
clang-tidy for userspace and eBPF parts; audit ELF using bpftool/libbpf, detection of
orphaned maps, invalid sections, unnecessary dependencies; analysis for race condition and
leaks.
Integration tests
Raising virtual machines with different kernel versions (QEMU, Vagrant); mass testing of the
load and functionality of eBPF programs, monitoring of validation errors, drop-rate,
assessment of the impact on latency/CPU.
Production-like
testing
Checking in Secure Boot, JIT disabled, with tail_calls/ringbuf disabled; fallback mechanics,
stress testing, degradation monitoring; Edge case profiling.
Chaos engineering
и observability
Conducting chaos testing: randomized restarts, network shutdowns, kernel manipulations;
collection and visualization of metrics in Grafana/Prometheus, automatic generation of
sustainability reports.
It is necessary to store all the results of unit/integration/chaos tests, logs, map dumps
and metrics, and link them to git commit hash for full traceability;
Static and dynamic analysis of eBPF ELF objects is automated using bpftool lint,
bpftool verify, and clang-tidy, which is critical for preventing runtime errors;
Regular profiling of all bottlenecks (hot-paths) and diagnostics of the impact of eBPF
on the performance of target systems (CPU, memory, I/O) become part of integration
and regression tests.
8.4 Recommended commands, scripts, and templates
Compilation and Include Generation
Explanation:
Compiles the eBPF program (tracer.bpf.c) to bytecode (tracer.bpf.o).
Generates the C header (vmlinux.h) for BTF (BPF Type Format) compatibility.
Loading and Pinning eBPF Programs with bpftool
Explanation:
Loads the compiled eBPF object file (tracer.bpf.o) into the kernel.
Pins the eBPF program to /sys/fs/bpf/tracer and the map events to
/sys/fs/bpf/events_map for persistent access.
Example systemd unit for Userspace Agent
Explanation:
Configures a systemd service for the userspace agent.
The agent is started with access to the BPF filesystem and the pinned map path.
The service will automatically restart on failure.
Example CI/CD YAML Pipeline
Explanation:
Build eBPF: Compiles the eBPF code and loads the program into the kernel.
Verify BPF: Runs a BPF verification or test run.
Run in VM: Spins up a virtual machine with Vagrant and executes integration or
system tests.
8.5 Advanced Best Practices: Automation, Monitoring, Operational
Sustainability
To reproducibility all builds and tests, it is necessary to save compilation artifacts,
vmlinux/BTF, system logs, map dumps and detailed run reports;
Embed automated profiling by metrics: drop-rate of events, CPU/memory overhead,
latency of the userspace agent, integrating the results into Prometheus/Grafana.
Metrics are labeled with unique identifiers for each build to analyze degradation and
find regressions;
In Kubernetes/cloud environments, use Helm charts and Operators to automate
deployment, updates, hot migrations (with pinned maps saved), and orchestration;
provide zero-downtime deployment and rollbacks without data loss;
Perform degradation emulation: chaotic restarts, kernel mode switching, testing on
old versions of the BPF framework to identify hidden portability problems;
Maintain detailed documentation at all stages: pipeline schemes, sample scripts,
YAML templates, fallback guides for unsupported kernel functions;
Use automatic integration with issue tracking systems (Jira/GitHub Issues) to create
tickets for failed tests, validation errors, or identified race conditions;
For advanced scenarios, there is integration with cloud-based CI/CD systems (GitHub
Actions, GitLab CI, Jenkins), automatic publication of docker/k8s agent images and
monitoring of their work in production through metrics and alerts.
9. Milestone Implementation Plan (Roadmap)
This stage plan is built on the basis of a comprehensive scientific and
methodological paradigm, which involves not only a step-by-step engineering
implementation, but also a comprehensive theoretical analysis of applicability,
formalization of hypotheses, empirical validation of design solutions, as well as
institutionalization of best practices in the development and operation of high-load
routing systems using eBPF. Each stage provides for a multi-level check of the
reproducibility, portability and validity of the selected architectural solutions, which
ensures the scalability, transparency and validity of the R&D process.
9.1 Phase I: Domain Research and Prototyping (2-4 weeks)
Definition of project scope and decomposition of requirements: In-depth analysis of
target programming languages, runtime environments and the most representative
frameworks (Go, C, Java, Node.js), identification of experimental test cases taking
into account synthetic (I/O, fork/exec, network transactions, HTTP handlers) and
real-world patterns, description of platform limitations and target use cases.
Building a minimum prototype: Implementation of an elementary eBPF tracer with
the implementation of kprobe (and, if necessary, uprobe) in test functions; formation
of a pipeline for transmitting events (timestamp, PID, function) via
perf_event_output/ringbuf; Standardize message format at the userspace level.
preparation of infrastructure for manual and automated testing.
Experimental validation and calibration: Multiple runs on reference and experimental
applications, accurate calibration of latency metrics using the example of sleep, IO,
file operations; quantitative analysis of the throughput of the event channel, overhead
per CPU, estimation of the minimum achievable response time. Ensuring
reproducibility of results and preparation of reporting documentation.
9.2 Phase II: MVP – Fundamental Tracing and Stacking (4-6 weeks)
Architectural scaling: Separation of the architecture into independent kernel-space
(eBPF) and user-space (agent) subsystems, integration of a modular configuration
layer (function patterns, extensible filtering by PID, namespace, binary names).
Development of a migration scheme between kernel versions, taking into account the
differences in BTF/CO-RE.
Systematization of data collection mechanisms: Introduction to the system of
collecting parameterization events (function name, PID, latency, call parameters),
implementation of structured reliability monitoring mechanisms (adding drop-rate
control, logging of transfer errors). Assess the reliability of operation under load,
including the simultaneous tracing of multiple processes.
Comprehensive testing and verification: Design and implementation of a complete
system of unit tests for userspace agents, integration scenarios on real and synthetic
loads (for example, file operations, multithreaded and network tests), comparison of
results with reference data, static and dynamic analysis of event coverage.
9.3 Phase III: Feature Enhancement – Handling Arguments and Call Stacks (3-
5 weeks)
In-depth analysis of arguments and call parameters: Extend the capabilities of eBPF
programs to extract not only scalar, but also pointer types using bpf_probe_read(),
process nested user structures, develop a mechanism for secure serialization and
deserialization of complex objects. Applicability analysis for different ABIs and
compiler versions.
Unwinding and call stack recovery: Implementation of a stack recovery mechanism
using bpf_get_stack() (if frame pointers are available), development of a fallback
mechanism via DWARF-CFI (with .eh_frame preprocessing, integration with
DWARF symbology parsers), comparison of the quality of reconstruction with
reference profilers (perf, gdb). Analysis of the overhead at each stage of stack
recovery, quantitative assessment of the correctness and completeness of the resulting
trace chains.
Advanced testing and validation: Multi-level testing on C, Go, deep recursion,
asynchronous calls, file and network load scenarios. Perform a comparative analysis
of the quality and completeness of extracted data for different architectures (x86_64,
ARM64).
9.4 Phase IV: Correlation of HTTP/gRPC and Asynchronous Calls (4-6 weeks)
TraceContext autogeneration and propagation mechanisms: Implementation of
traceparent/tracestate header extraction algorithms from HTTP/2, HTTP/1.1, gRPC
protocols; automatic generation and propagation of trace-id into egress traffic;
Formation of SPAN chains with support for multi-level correlation, even with partial
loss of context. Compatibility assessment with OpenTelemetry, Zipkin, Jaeger,
Tempo.
Black-box correlation and fallback methods: Matching network flows through 5-tuple
analysis, stateful caching of trace-id in BPF maps, development and validation of
fallback correlation methods for applications without header support. Study of the
limits of the method's applicability (operability under NAT, multi-tenant
environments, dynamic IP/port changes).
End-to-end testing, stability analysis: Building complex scenarios with service chains
(client → services in Go/Java → visualization in Jaeger/Tempo/Prometheus),
emulation of production loads, fault tolerance study for variations in kernel
parameters (Secure Boot, lockdown, lack of bpf_probe_write_user support), trace-
loss analysis and degredation impact.
9.5 Phase V: Filtering, Sampling, and Dynamic Adaptation (2-4 weeks)
Integration of advanced configurable filtering: Implementation of flexible filtering by
PID, namespace, ports, gRPC methods, HTTP methods, support for masks and
pattern matching, adaptation for container environments (cgroup, container ID).
Implement incremental changes without rebooting the kernel (runtime reconfig).
Flexible sampling strategies and dynamics: Implementation of sampling for each Nth
event, latency-based and time-windowed sampling; dynamic enabling/disabling of
tracing via BPF map and signals from userspace; algorithms for automatic adaptation
of sampling rate to load conditions.
Load testing and efficiency analysis: Load profiling of eBPF programs on the cluster,
emulation of load peaks, quantitative assessment of CPU/IO overhead, analysis of the
effectiveness of selected sampling/filtering strategies, collection of statistics on
impact on latency and reliability.
9.6 Phase VI: eBPF Code Optimization and Extreme Scenario Testing (3- 4
weeks)
Modular refactoring and optimization: Decomposition of programs into tail-call
chains, optimization of the structure and size of BPF maps, minimization of bytecode
size, verification through statically analyzable workflows, elimination of redundant
or potentially ineffective instructions.
Multi-level static and dynamic verification: Implementation of bpftool verify/lint,
clang-tidy tools for userspace and eBPF components, integration into CI/CD
pipelines; Tracking statistics of errors, incorrect uploads, fragmentation of BPF maps
and degradation of performance in non-standard kernel modes.
Extreme load tests: Conduct large-scale load and stress tests (10k+ events/sec,
simulate long-term peak loads), analyze the latency and efficiency of eBPF programs
in conditions of disabled JIT, no ringbuf/tail_calls, stability monitoring on
heterogeneous cores and virtualized environments.
9.7 Phase VII: Documentation, implementation of CI/CD and formalization of
auto-testing (2-3 weeks)
Formalization and standardization of engineering documentation: Development of
detailed architectural and sequence diagrams, description of commit/review
workflow, formalization of code review standards and validation, standardization of
CI/CD processes, detailed specification of requirements for reproducibility and
traceability.
Automation of CI/CD processes and extended test coverage: Coverage of all modules
and components unit/integration/chaos tests; organization of multikernel verification
(various cores, QEMU, containerized environments), automatic aggregation and
analysis of reports, configuration of monitoring tools and alerts at the testing stage.
Development of ecosystem examples, templates and practical recommendations:
Formation of Helm charts for Kubernetes, unit files for systemd, Dockerfile samples,
use cases with release documentation and changelog; preparation of
recommendations for implementation and operation in different types of
infrastructure.
9.8 Phase VIII: Release, Operation, Support and Evolution of the Solution
(Continuous)
Versioning and maintenance strategy: Use of strict SemVer, support for release notes,
formalization of notification procedures and documentation of backward-
incompatible changes, automation of update release processes.
Monitoring, operation and reliability control: Integration with monitoring systems
(Prometheus, Grafana) to collect complex metrics (latency, events, drop-rate),
tracking CPU/Memory profiles, regular operational validation of stability under real
and extreme loads, performance control in non-standard production scenarios.
Feedback, user support and retrospective analytics system: Integration of issue
tracker, SLA/RPO metrics, organization of incident retrospectives, ensuring a high
level of interaction with end users and integrators, quick feedback on offers and
detected bugs.
Architecture evolution and extensibility of the solution: Continuous work to expand
support for new kernel versions, new BTF features, updating support for new
frameworks, languages and observability techniques, flexible migration support,
testing new experimental features, ensuring backward compatibility.
10. Risks and mitigation strategies
10.1 Linux kernel version compatibility and eBPF API evolution
In the process of designing and implementing universal eBPF tracers, one of
the most significant challenges is to ensure stable compatibility with a wide range
of Linux kernel versions that are used in various production and enterprise
environments.
Specific features such as fentry/fexit, extended support for BTF (BPF Type
Format), improved CO-RE (Compile Once – Run Everywhere) mechanisms, and
new eBPF helpers appear only in a number of relatively modern kernel versions
(e.g., fentry is available from 5.3, BTF requires CONFIG_DEBUG_INFO_BTF,
significant API extensions are observed after the 5.4 and 5.8 releases). This
significantly limits the potential portability of tools between systems, creates
additional risks when operating in heterogeneous clusters, and also complicates the
task of unifying the tracing architecture in large infrastructures.
Legacy kernel support, especially in environments with long-term support
(LTS) policy and custom builds, requires a thorough analysis of the availability of
eBPF features and the construction of adaptive fallback mechanisms.
Mitigation measures:
Enable a multi-level feature-probing stage during the deployment phase and at every
update: Automate the scanning of kernel capabilities through bpftool feature probe to
identify available eBPF instructions, maps, hook types, and other primitives.
Development of a strategy for dynamic loading and selection of optimal eBPF code
from fallback to low-feature modes (for example, auto-replacement of fentry with
kprobe, switching ringbuf → perf buffer, using user-space unwinding in the absence
of support for stacked eBPF operations).
Creation and maintenance of extensive documentation on minimum requirements,
versioned compatibility matrix and automated feature-availability reports for DevOps
teams and users of the tool.
Implementation of automated integration testing procedures on multiple
VMs/containers with different kernels (QEMU, virtme, CI-CD pipelines) to validate
the behavior of tools on all target configurations.
10.2 BTF Unavailability and DWARF Integration Limitations
Support for BTF metadata is a cornerstone of the modern eBPF ecosystem
today, especially for CO-RE implementation and efficient operation with typical
security, structured access to kernel memory layout and applications. However, on
many servers, the BTF is unavailable (CONFIG_DEBUG_INFO_BTF VMLINUX
with the necessary partitions is disabled, missing, or not loaded), which drastically
reduces the ability to autogenerate secure eBPFs and makes it difficult for runtime
to relocate. DWARF integration, despite its flexibility and breadth of support,
requires complex preprocessing pipelines (pahole, eh_frame generation, external
parsers), which leads to an increase in build-time, an increase in resource intensity
and susceptibility to errors, especially with frequent releases or non-standard builds.
Mitigation measures:
Implementation of the policy of mandatory BTF support for all production hosts,
automation of vmlinux construction and BTF generation for any kernel update
(pahole, vmlinux-to-btf-based scripts, bpftool btf dump).
Implementation of a hybrid dual-mode mode: fallback to DWARF parsing if BTF is
absent, and limiting the DWARF mode only to the most demanding use-cases (deep
async stacks, JIT code); for the main trace, reliance on frame pointers (FP) and
minimization of typical information requirements.
Detailed description of requirements for the core and build infrastructure, automatic
notification of users about the impossibility of performing relocated operations in the
absence of BTF.
Integration testing of BTF/DWARF generation processes on CI stands, validation of
the correctness of structure recognition on different cores and architectures (x86_64,
arm64).
10.3 Overhead and performance degradation from eBPF instrumentation
A significant risk is that poorly optimized eBPF instrumentation can not only
create a point of performance degradation (CPU, memory, IO), but also potentially
lead to SLA/SLO violation incidents in high-load clusters. High frequency of events
(for example, during mass monitoring of short-lived processes or with detailed
library tracing), aggressive log events, and unoptimized filtering logic can lead to a
saturate CPU, an increase in the drop-rate in BPF maps, and a deterioration in
latency-critical workflow.
Mitigation measures:
Architectural principle of primary filtering: maximum transfer of filters (PID,
namespace, cgroup, port, method, path, etc.) to the eBPF code, minimization of the
transfer of irrelevant events to the userspace.
Advanced sampling strategy: latency-based sampling (send events only when the
delay threshold is exceeded), fixed-rate sampling (every Nth event), dynamic
sampling by BPF map flag.
Integration with monitoring systems: exposure of metrics through Prometheus (drop-
rate, lost events, avg latency, memory footprint), automated alerts and sampling rate
adjustment in response to load growth.
Use of backoff and automatic throttling: temporary disabling of tracing when load
thresholds are reached, automatic restart of agents, segmentation of loads by groups.
Continuous analysis and profiling of eBPF code performance in CI, load tests at
volumes close to real production.
10.4 Security Threat Vector and Critical Data Protection
The use of eBPF programs is associated with access to sensitive information,
including arguments of user and system functions, package structures, and
interprocess interactions. Validation problems, privilege escalation through verifier
defects or vulnerabilities in the JIT compiler, as well as bugs in the BPF maps
management logic, can lead to the compromise of entire infrastructure segments.
Mitigation measures:
Implementation of LSM (SELinux/AppArmor/LSM BPF) to restrict the rights of
eBPF programs, configuration and auditing of ACLs for pinned maps, isolation of
user and system spaces.
Use end-to-end TLS/SSL for all data transfer channels between the core and the
userspace agent, log all operations with sensitive data, monitor suspicious activity at
the maps level.
Implementation of defense-in-depth practices: Hardware-assisted sandboxing (MPK,
eBPF SFI), constant peer-review and audit of the source code (pull request with
mandatory review of the security lead), regular updating of the kernel verifier and
security-advisory monitoring (SafeBPF, MOAT, CVE).
• Conducting training sessions for DevOps and SecOps teams, modeling attacks and
responding to potential incidents, escalation tests (Red/Blue Team).
10.5 Secure Boot / Lockdown Mode Limitations
In advanced security-oriented environments (public cloud, FinTech, state),
Secure Boot/Lockdown kernel modes are activated, as a result of which a number of
eBPF helpers (in particular, bpf_probe_write_user, tracepoint-helper) become
inaccessible to users. This limits the automation of TraceContext injection,
monitoring of userspace programs, interference with applications, and reduces the
quality of distributed correlation.
Mitigation measures:
Automated feature detection: scanning the Secure Boot/Lockdown mode before
loading eBPF programs, dynamic switching to black-box correlation (tuple-based
matching, network-layer tracing) if it is impossible to write to userspace memory.
Support and documentation of fallback mechanisms: a detailed description of
possible limitations, recommendations for architects and operators to change security
settings for full-fledged tracing, instructions on potential trade-offs (delays, reduction
of detail).
Implementation of self-healing procedures: automatic shutdown or degradation of the
eBPF agent functionality when critical helpers are detected, detailed event log for
post-mortem analysis.
10.6 Complexity and complexity of DWARF-parsing integration for stacks
DWARF stack parsing is a computationally complex, resource-intensive, and
error-prone process that requires the generation and maintenance of additional
artifacts (eh_frame, symbol-table, external parsers). In conditions of intensive
production tracing or when you need to profile applications with dynamically
generated stacks, excessive use of DWARF can lead to a dramatic increase in latency
and resource consumption.
Mitigation measures:
Using frame pointers as the main stack build mechanism for most production
scenarios, providing control over the inclusion of FP at the compilation stage of the
target application (for example, Go with the -gcflags="-N -l" option).
Limitation of DWARF mechanisms only for deep debugging and analysis of edge-
cases (just-in-time code, asynchronous threads, dynamic languages), dynamic
switching to DWARF parsing only in debug mode.
Automating eh_frame preprocessing, testing compatibility on various builds,
providing fallback to easier unwinding modes when DWARF problems are detected.
10.7 Limitations of eBPF testing and debugging difficulties
Debugging and testing eBPF code in kernel space is associated with
fundamental limitations: small stack, lack of standard debugging tools, the need to
pass a verifier, runtime errors, instability in different cores, race conditions under
parallel loads. The possibility of subtle bugs increases with the complexity of
programs and the increase in the number of integrations.
Mitigation measures:
Implementation of multi-level test scenarios: automation via bpftool prog test run,
integration of dry-run modes into CI/CD, building special emulating test
environments based on QEMU and kernel selftests.
Support for advanced logging, rate-limiting and aggregation of only events with
diagnostic value; introduction of "observability lead" roles and mandatory regular
peer-review of all changes in eBPF programs.
Building a library of typical unit tests of userspace components, systematic use of
fuzzing to identify edge-case scenarios, monitoring and responding to anomalies
using Prometheus.
System automation of post-incident analysis, deep coverage with metrics and
building models of bug reproducibility.
11. Recommendations and best practices for the development and
operation of eBPF tools
11.1 Use of BTF as a standard of kernel type information
Modern paradigms for building eBPF solutions require prioritizing the use of
BTF (BPF Type Format) as a single, synchronized source of information about the
kernel structure and loaded modules. By enabling
CONFIG_DEBUG_INFO_BTF=y in the kernel configuration and having a valid
vmlinux artifact with full-size BTF metadata, developers can opt out of manual
management of includs and types in eBPF programs. This approach ensures strict
consistency with the current kernel version, eliminates the problems of mismatched
fields and structure sizes, and greatly facilitates the migration and portability of code
between different OS releases. BTF, as the foundation for CO-RE (Compile Once -
Run Everywhere), minimizes the risk of "type drift" even when changing the ABI
or rebuilding the kernel, allowing you to build truly portable eBPF tools.
To prevent synchronization discrepancies and race-conditions between header
files and BTF metadata, it is recommended to implement automated data integrity
validation using bpftool feature probe, build fallback chains in the absence of BTF,
and implement regular relevance checks in CI/CD.
11.2 Principles of optimizing eBPFs for verifier constraints
The Linux kernel verifier imposes extremely strict and formalized
requirements on the security, determinism, and predictability of eBPF bytecode. The
restrictions apply not only to the stack depth (≤512 bytes) and the length of the
instruction chain, but also to the nature of the use of variables, pointers, and
branches. Any loops with an unfixed number of iterations, excessive recursion, and
complex arithmetic are absolutely prohibited. Design best practices include:
Eliminate nested loops, transfer recursive or resource-intensive patterns to userspace;
Use unrolled loops only with full guarantees of output and predictable resource
consumption;
Splitting large programs into micromodules using tail calls (which also allows you to
bypass size and stack limits);
Strict decomposition of functions according to the principle "core — only collection
and filtering, userspace — aggregation, post-processing, export";
Document all constraints and automatically verify the eBPF bytecode (bpftool verify)
at every stage of the lifecycle.
It is recommended to configure linting and static analysis systems (clang-tidy,
bpftool, libbpf-tools) in order to anticipate verification errors at the development
stage, as well as to regularly run stress tests on production-like environments with
different kernel configurations.
11.3 Maintaining a modern dependency and tool stack
The eBPF ecosystem is characterized by a high pace of development: dozens
of new helpers appear every year, libraries (libbpf, bpftool, BCC, bpftrace) are
evolving, and the capabilities of CO-RE and vmlinux-oriented solutions are
expanding. It is extremely important not only to regularly update the tools used, but
also to fix the minimum versions, integrate their control into CI/CD, and monitor
the releases of the LTS kernel and public libraries. It is especially critical for
production systems to maintain up-to-date libbpf and bpftool, as new versions
contain important security patches, CO-RE extensions, support for new BPF maps,
and ringbuf/perf buffer optimizations.
It is also recommended to periodically audit and review dependency
manifests, create your own release calendar, monitor CVE vulnerabilities in third-
party tools, and implement automated compatibility checks during the testing phase.
11.4 Sensitive Data Security and Handling Management
eBPF programs, having the ability to introspect system and user calls, can
potentially capture and transmit sensitive, personal and service data. To build a
trusted environment and minimize risks, the following measures are required:
Strict differentiation of access rights to pinned BPF maps (use of fine-grained ACL,
LSM mechanisms, SELinux/AppArmor);
Protection of data exchange channels between the kernel and userspace (TLS,
protected IPC, socket pairs with enforced security policy);
Implementation of full-fledged RBAC systems and mandatory audit of logs for
anomalies, unauthorized access and leaks;
Storage of intermediate and historical data only in secure storages with disk
encryption and a strict rotational mechanism;
Conducting regular pentests and fuzzing campaigns for race-conditions, attacks via
JIT/JOP/Spectre and violation of the principles of least-privilege access.
It is recommended to implement your own policy enforcement mechanisms
on the userspace agent (for example, dynamic access revocation), integrate
monitoring systems (Prometheus, Grafana, Zabbix), and formalize the incident
response process.
11.5 Load monitoring, error handling and metrics management
The logic of loading, executing and interacting with eBPF programs should
be accompanied by multi-level monitoring, including:
Advanced logging of the status of loading, verification, deletion, update of BPF
objects (bpftool, userspace hooks);
Introduction of complex metrics: successful/failed downloads, drop-rate dynamics,
latency, map fill rate, sampling/filtering metrics, tail call misses and initialization
failures;
Setting up alerting mechanisms with the ability to integrate into external response
systems (Prometheus AlertManager, Sentry, PagerDuty, Teams/Slack, SIEM);
Systematic export of all metrics for subsequent anomaly analysis, incident
correlation, and proactive detection of performance degradation;
Building self-healing processes with automatic restart of the userspace agent and/or
reloading of eBPF programs in case of failures, limit exceeds, or SLA degradation.
To increase reliability, it is recommended to implement certain components
of resiliency logic: automatic backup of the state of cards, a mechanism for storing
critical events in the out-of-band log, the ability to dynamically change
sampling/filtres via API.
11.6 Choice of development tools and strategies: libbpf vs. BCC/bpftrace
In terms of performance, scalability, and support for modern features, libbpf
is now considered the de facto standard for production-grade eBPF tools. It provides
full support for CO-RE, tail calls, ringbuf, dynamic hook binding, detailed feature
probing and fine-grained error handling. BCC and bpftrace are suitable for
prototyping, rapid hypothesis validation, debugging, but their use in large, long-
lived systems is limited due to overhead, low flexibility, and the lack of some control
options.
It is recommended not only to fix the supported versions of libbpf, bpftool,
and kernels, but also to build a multi-level fallback strategy: test compatibility with
legacy kernels, ensure the replaceability of individual components (for example,
replace ringbuf with perf buffer), conduct integration tests with real load and
different hook types.
11.7 Validating and Documenting the Environment Configuration
Before bringing eBPF tools to production, it is extremely important to conduct
deep validation of support for all necessary kernel features (BPF, kprobes, uprobes,
dentry, tail calls, ringbuf, BTF, LSM, JIT, perf events, etc.). This is done through
bpftool feature probe, as well as through your own validation scripts and
documentation. The resulting reports should be stored in VCS, accompanied by
release notes, integrated into CI/CD, and available for audit and incident recovery.
It is also recommended to form a central register of all dependencies (kernel,
utilities, libraries, features), and to run automatic smoke and chaos tests for
production, emulating edge-cases and rare crash scenarios.
12. eBPF and userspace agent code examples
12.1 Minimal eBPF tracer (kprobe, CO-RE, C)
Analysis and comments:
The program is fully portable through the use of CO-RE and automatic BTF pulling
via vmlinux.h.
In the event_t structure, you can expand the set of transmitted data, including, for
example, the capture of specific arguments, errors, timestamps.
The inclusion of the syscall_nr field illustrates the extensibility of the event structure,
which is useful when you need to build a generalized tracer.
To build full-fledged profilers, it is recommended to extend stack trace processing
(for example, via bpf_get_stackid()).
Using bpf_perf_event_output is a standard practice for passing events to user space
for low-level tracing.
12.2 Userspace Agent on Go (libbpfgo): detailed decoding, aggregation, and
advanced metrics
Case study:
Not only the reception and decoding of events is demonstrated, but also the
aggregation of statistics, such as per-PID calculation and the construction of latency
histograms, which is important for scientific performance analysis.
The code structure fully complies with the best practices of modern userspace agents:
clear shutdown, histograms, SIGINT interception, transparent error handling.
Can be extended by exporting to OpenTelemetry/Prometheus (via push metrics).
12.3 Skeleton-API and advanced userspace (C): dynamic filtering, CI/CD
integration
Key aspects:
Using the bpftool gen skeleton API allows you to bind the eBPF structure and
userspace in a strongly typed and safe way, which is critical for CI/CD.
Demonstration of passing filtering variables from userspace to BPF via .rodata
sections (most relevant for production monitoring).
In real-world scenarios, filtering can be extended to namespace, UID, syscall
arguments, and so on.
12.4 XDP Tracing and Network Metrics Aggregation (C+Go)
eBPF C (packet counter with XDP)
Go: Userspace agent for network packet aggregation
Features:
XDP code is in demand for network traffic analysis, DDoS protection, and reactive
optimization in cloud-native infrastructures.
In real systems, XDP is used to reduce latency at the L2/L3 levels, and the userspace
agent additionally aggregates statistics on flows, IP, QoS, etc.
The example can be extended to stream aggregation (Per-CPU array maps, LRU hash
maps).
12.5 Call Stack: stack_map Integration and Deep Profiling
eBPF (C): Building a call stack for post-mortem analysis
Go userspace: Decoding the stack trace and displaying the profile
Aspects for research work:
Using stack_map and associating the PID with the stack id allows you to build a
flamegraph, analyze deadlock- and lock-contention situations.
In complex cases, DWARF-unwinding is implemented in userspace (for example, via
py-spy/Parca).
This pattern is an industry standard for debugging race conditions, anomalies, and
rare path execution.
13. Dependencies and terminology glossary for eBPF projects
13.1 Programming languages and development environment
C is a fundamental language for creating eBPF programs, which is necessary for the
most granular control over the low-level aspects of interaction with the Linux kernel.
The code of eBPF programs in C is compiled using LLVM/Clang into bytecode
suitable for loading into the kernel, taking into account all its limitations (no dynamic
allocations, strictly fixed stack, only a limited set of supported types and operations).
This approach provides portability, the ability to build static security guarantees, and
tight integration with the kernel verification system (eBPF Verifier).
Go, Python, Rust, C# are top-level languages used to implement userspace agents.
These agents are responsible for loading and binding BPF programs, deserializing
events from BPF maps (including ringbuf/perf buffer), correlating metadata,
aggregating metrics, and subsequent integration with monitoring and visualization
systems (Prometheus, Grafana, Jaeger, Tempo, OpenTelemetry). Rust and C# are
used in scenarios that require formal verification or integration with enterprise
ecosystems.
Shell/Bash are indispensable tools for automating all stages: build (Makefile, shell
scripts), deployment, CI/CD, installing dependencies, configuring production and test
environments (Kubernetes, systemd, Ansible). Within the framework of mature
projects on Bash/Shell, auxiliary utilities are usually implemented for mass
compatibility checking, feature-probing, BTF version migration, etc.
13.2 Compilers, SDKs, and build tools
clang/LLVM is a required tool stack for compiling eBPF C code into ELF objects
with support for BTF, CO-RE, advanced optimizations, and static analysis. Support
for the latest versions of Clang/LLVM is critical for the use of CO-RE, modern
relocation, efficient generation of BPF instructions, and proper interaction with the
BPF Verifier of the kernel. In advanced pipelines, it is recommended to use separate
build images with precisely fixed clang/llvm versions.
libbpf is a modern C-library for managing BPF programs, supporting the BPF
skeleton API (automatic generation of .skel.h), dynamic loading and linking of eBPF
to BTF, management of all major types of BPF maps and feature-detection. libbpf is
the standard for production solutions due to its high stability, support for new kernel
features, and tight integration with CI/CD tools, including automated skeleton
generation and testing.
BCC (BPF Compiler Collection) is a powerful Python SDK for prototyping,
interactive analysis, and educational experiments. It allows you to quickly implement
complex tracing scenarios, but due to the presence of significant runtime
dependencies and additional overhead, it is mainly suitable for proof-of-concept and
laboratory tasks.
libbpfgo is a Go wrapper over libbpf that greatly simplifies the development of
production-grade userspace agents in Go with full support for CO-RE, BPF maps,
perf buffer, ringbuf, and skeleton API. It is relevant for large distributed systems
focused on performance and cross-platform.
bpftool is the main CLI tool for interacting with the eBPF stack: program loading and
testing, feature-availability analysis, skeleton generation, BPF maps inspection,
dynamic detection of kernel capabilities, testing for support for new features (bpftool
feature probe).
13.3 Kernel, header files, BTF, and DWARF
linux-headers / kernel-devel — a complete set of Linux kernel header files required
for the correct assembly of eBPF programs with CO-RE support, relocatable ELF
objects, and safe interaction with kernel structures. You should use headers that
strictly match the target kernel to exclude mismatch.
BTF (BPF Type Format) is a machine-readable binary metadata format about the
types of structures, variables and functions of the kernel and its modules. BTF
eliminates the need for manual synchronization of custom headers, provides
portability of eBPF programs, automatic application of CO-RE relocation, and
expands inspection capabilities (bpftool btf dump). For correct operation, it requires
enabled flags CONFIG_DEBUG_INFO_BTF=y,
CONFIG_DEBUG_INFO_BTF_MODULES=y (starting from 4.14, 5.x+ is
recommended).
DWARF, CFI (Call Frame Information) are complex formats of debugging
information necessary for implementing deep unwinding of user stacks, especially in
cases where there are no frame pointers (for example, when working with JIT code,
JVM, Go). To generate BTF from DWARF, the pahole (dwarves) tool is used, which
requires an up-to-date version (1.16–1.21 and higher, depending on the core).
DWARF-5 expands support for complex cases, including custom ABIs, coroutines,
and hybrid trace scenarios.
13.4 Serialization and network exchange libraries
protobuf, JSON are generally accepted serialization formats for the exchange of
events, metrics, and aggregated data between userspace agents and backend services
(for example, collectors and observability stacks). The choice of format should be
dictated by the requirements for compatibility (OpenTelemetry, Jaeger, Tempo),
latency, ease of integration with the microservice architecture, and the need to transfer
nested structures.
The HTTP/gRPC library is a tool for implementing trace context propagation, passing
metrics, injecting Trace-ID into headers, supporting distributed correlation, and
integrating the eBPF tracer with external monitoring systems. They are necessary for
building full-fledged trace chains in cloud and microservice architectures.
13.5 Linux kernel: requirements and considerations
Basic support for eBPF is implemented in the 4.x kernels, but the 5.x+ kernel (CO-
RE, BTF, uprobes, fentry/fexit, ringbuf, hash of maps, advanced helper functions) is
recommended to take full advantage of all the features. For example, fentry/fexit are
implemented in 5.3+, CO-RE relocation — from 5.4+, ringbuf — from 5.8+. It is
important to choose and maintain LTS kernels (4.19, 5.4, 5.10, 5.15+), systematically
test features through the bpftool feature, enable monitoring of supported options in
CI/CD, and control compatibility between development and production
environments.
13.6 Glossary of eBPF Stack Terms and Key Concepts
eBPF (Extended Berkeley Packet Filter) is a high-level dynamic Linux kernel
extension technology that provides a sandbox for running secure user programs with
deep integration with the network stack, security subsystem, file system,
observability, and monitoring infrastructure. eBPF implements a programming model
in which code is verified, compiled into bytecode, and run in the context of a kernel
with severe security constraints.
kprobe / uprobe are dynamic function interception points that allow tracing system
calls and kernel-level events (kprobe) or any functions in user ELF binaries and
shared libraries (uprobe). They are critical for analyzing the behavior of both system
services and user applications.
BTF (BPF Type Format) is a compact binary format of typical information for
structures, variables, and kernel/module functions. Allows eBPF programs to
automatically adapt to differences between kernel versions without the need to
maintain separate header files, eliminating desync and simplifying the relocation and
migration of production code.
DWARF, CFI (Call Frame Information) is a debug information storage format used
for deep unwinding of execution stacks in complex traces. It is important for profilers,
support for languages with just-in-time compilation (JVM, Go), as well as for manual
analysis of complex cases of asynchronous calls.
Tail Call is a mechanism for transferring control between eBPF programs in the
kernel without increasing stack depth, which breaks down logic into modular
components, allowing you to bypass the size and complexity limitations of individual
programs.
BPF map is a universal structure for exchanging and storing data between eBPF and
user-space. Various types are supported (array, hash, LRU, stack_trace, ringbuf, perf
buffer, etc.), each of which is designed for its own field of application (metric
aggregation, correlation, context exchange, event transfer).
Trace context / Trace ID is a unique identifier of a distributed request (e.g., W3C
traceparent, OpenTelemetry Trace/Span ID) passed through HTTP/gRPC headers
and used to implement end-to-end event correlation in microservice and distributed
systems.
Sampling is a set of techniques for selecting only a subset of events (for example,
latency-triggered sampling, Nth event) in order to reduce the load on the kernel,
userspace agents, network infrastructure, and backend observability services.
CI/CD (Continuous Integration / Continuous Delivery) is a set of techniques and tools
for automating the processes of building, testing, analyzing and delivering eBPF tools
to production. Includes multi-core testing (different kernel versions, security flags —
Secure Boot, lockdown, no JIT), feature-probing, automatic dependency
documentation, integration with monitoring and alerting systems.
Generalized conclusions on the implementation of a universal eBPF
tracer
Modern universal eBPF tracers are built on the principles of a strictly modular,
hybrid architecture that integrates several layers of data collection, aggregation, and
analysis. The Linux kernel runs eBPF/CO-RE programs that can interact with both
system functions (via kprobe/fentry/fexit) and user runtimes via uprobes and user-
level tracepoints. For maximum portability, support for BTF (BPF Type Format)
and DWARF is implemented, which allows you to reconstruct the types and call
stack regardless of the kernel version and the specifics of the user binary.
Conceptually, this architecture acts as a universal layer between different
language ecosystems (Go, JVM/Java, Python, Node.js, Rust, etc.), allowing for deep
polymorphic tracing with support for both static and just-in-time or interpreted
languages. For example, in modern systems, it is possible to trace gRPC, HTTP, file,
and interprocess calls in heterogeneous microservices applications at the same time
without the need to inject additional code or agents into each application.
Example of practical implementation:
Go: uprobes are embedded in runtime libraries to capture goroutine events and
network operations;
Python: tracing the interpreter via libpython hooks and parsing calls to C-extension
modules;
JVM: Through the trace of JNI and just-in-time functions, with analysis of
asynchronous operations.
Multi-Level Event Correlation: Advanced Scenarios and Limitations
To provide end-to-end visibility of distributed and parallel processes, the
eBPF tracer implements a comprehensive correlation model that combines:
TraceContext inline injection (e.g., W3C traceparent): automated reading, distribution, and
injection of transaction identifiers in HTTP/gRPC or other RPC protocols, implemented in
eBPF programs by parsing system/application call arguments.
Contextual binding of asynchronous threads: tracking and storing parent and child thread
identifiers (goroutine, thread ID, async_id). This allows not only to store trace-ids between
asynchronous calls, but also to build full-fledged chains of distributed transactions, including
cross-language transitions.
Black-box network correlation: a fallback strategy based on monitoring unique network
tuples (src/dst IP, port, proto) when an explicit TraceContext is not available. This technique
allows you to associate events passing through the kernel, even in the absence of explicit
support for distributed tracing in the application.
Effects:
Maintaining the integrity of distributed paths for microservices of any type, including
high-load cloud clusters.
Trace chain recovery with "black boxes" (for example, third-party libraries), which
is impossible in user-level agent approaches.
Performance, resiliency and information security
To overcome the limitations of the kernel, verifier, memory and CPU
resources, as well as attacks on the surface of the BPF subsystem, the following
combined mechanisms are used:
Dynamic and hybrid sampling: adaptive selection of the intensity of event collection
(Nth selection, latency-triggered, SLA-based) depending on the load, which allows
you to control the overhead (<5% of the CPU in intensive scenarios).
TTL for BPF map and memory control: regular cleanup of stale keys, monitoring of
allocated memory and limits (BPF map limits, hard/soft quota), prevention of OOM
and service degradation.
Security: implementation of eBPF programs only in a signed or verified form, strict
isolation of BPF maps using LSM (SELinux, AppArmor) and role-based access
control, encryption of IPC channels between the kernel and userspace. Continuous
audit of eBPF loading and execution events with violation logging and dynamic
alerts.
Operational scenarios
For incidents, 100% trace on error-path is applied;
For background monitoring: sampling 0.1–1% for services with high QPS;
Latency histograms are built in the core for on-the-fly analysis of tail latency;
Fallback: Automatically switch to BTF-only analysis in the absence of DWARF.
Operation, automation and dynamic control
To ensure operational sustainability and support reproducibility, CI/CD is
used with the following steps:
Cross-core build and multiversion: CO-RE, skeleton API, automatic generation of
.skel.h to support 5.4+, 6.1+ kernels;
Integration with the test and production environment: bpftool feature probe, self-tests,
automated SBOM dependency analysis, Secure Boot/Lockdown compatibility audit;
Dynamic configuration (runtime API)
Modular trace activation, the ability to update filters and sampling strategies without
stopping the agent (via BPF map or RPC API).
Business Effects, Scalability and Cost-Effectiveness
Engineering and management metrics:
Observability: >90% complete stack coverage without the need to modify the source
code of applications;
Reduce MTTR: Reduce diagnostic and recovery time by 30% to 40% with end-to-
end tracing and automatic event correlation;
Integration: compatibility with existing observability stacks (Prometheus, Grafana,
Jaeger, Tempo, OpenTelemetry, Loki, etc.) through open standard interfaces;
Implementation time: standard project — 14 – 18 weeks, taking into account
integration and load testing;
Multi-language support: unified architecture for Go, Python, JVM/Java, Node.js,
Rust, including interaction with JIT and native extensions;
Lower Total Cost of Ownership (TCO): Up to 30% lower than proprietary
APM/Observability platforms due to open-source, simplified CI/CD, and lower
implementation and support costs.
Academic Insights, General Scientific Conclusions and Paradoxes of
Architecture
With the increasing versatility of the eBPF tracer (support for new languages,
extensibility), the need for specialized modules to support just-in-time (JIT), dynamic
extensions, and optimized parsers for language runtimes (e.g., sub-agent allocation
for JVM/Go) increases exponentially.
The main trade-off is between the breadth of applicability, operational overhead,
complexity of debugging, and the need to dynamically balance the depth of collection
and aggregation. To minimize overhead and increase reliability, eBPF features auto-
detect (bpftool probe), dynamic feature-flags and policy-driven sampling/filtres are
used.
The key principle of reproducibility is CI/CD automation with testing on multiple
cores and architectures, monitoring of changes to BTF/DWARF/BPF map features,
a strict bundle of sources, binaries, and documentation.
Formalization of traceability of artifacts (VCS), publication of all test, operational,
and monitoring metrics in conjunction with a specific code version (infrastructure as
code & observability as code).
Final evaluation
The comprehensively implemented eBPF tracer, built on the basis of the
stated scientific principles, provides reliable, transparent, flexible and industrially
scalable observability in multi-lingual and heterogeneous infrastructures. This
approach combines the academic rigor of the analysis methodology with operational
agility and the absence of application change requirements, which distinguishes it
from all traditional APM and monitoring models.
This is a offline tool, your data stays locally and is not send to any server!
