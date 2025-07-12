#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_PACKET_SIZE 1500
#define MAX_HTTP_HEADERS 512
#define MAX_FLOWS 65536

// Network flow key for tracking connections
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 direction; // 0=ingress, 1=egress
};

// Network flow statistics
struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
    __u32 tcp_flags;
    __u16 http_requests;
    __u16 http_responses;
    __u8 flow_state; // 0=new, 1=established, 2=closing, 3=closed
};

// XDP packet event for userspace
struct xdp_event {
    __u64 timestamp;
    __u32 ifindex;
    __u32 rx_queue;
    __u16 packet_size;
    __u16 payload_offset;
    __u8 protocol;
    __u8 direction;
    __u8 action; // XDP_PASS, XDP_DROP, XDP_REDIRECT, etc.
    
    // Network headers
    struct flow_key flow;
    
    // HTTP detection
    __u8 is_http;
    char http_method[8];
    char http_path[64];
    __u16 http_status;
    
    // Performance metrics
    __u64 processing_time_ns;
    __u32 cpu_id;
    
    // Packet data (first 256 bytes for analysis)
    __u8 packet_data[256];
};

// Maps for XDP tracing
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} xdp_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flow_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} byte_counter SEC(".maps");

// XDP configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} xdp_config SEC(".maps");

// Configuration keys
#define CONFIG_ENABLE_HTTP_DETECTION 0
#define CONFIG_ENABLE_FLOW_TRACKING  1
#define CONFIG_ENABLE_PACKET_CAPTURE 2
#define CONFIG_MAX_PACKET_SIZE       3
#define CONFIG_SAMPLING_RATE         4

// Helper functions for eBPF compatibility
static __always_inline int bpf_memcmp(const void *s1, const void *s2, int n) {
    const char *p1 = (const char *)s1;
    const char *p2 = (const char *)s2;

    #pragma unroll
    for (int i = 0; i < n && i < 16; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}

static __always_inline void bpf_memcpy(void *dest, const void *src, int n) {
    char *d = (char *)dest;
    const char *s = (const char *)src;

    #pragma unroll
    for (int i = 0; i < n && i < 64; i++) {
        d[i] = s[i];
    }
}

static __always_inline void bpf_memset(void *s, int c, int n) {
    char *p = (char *)s;

    #pragma unroll
    for (int i = 0; i < n && i < 512; i++) {
        p[i] = c;
    }
}

// Helper function to parse Ethernet header
static __always_inline int parse_ethernet(void *data, void *data_end, __u16 *eth_proto) {
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end) {
        return -1;
    }
    
    *eth_proto = bpf_ntohs(eth->h_proto);
    return sizeof(struct ethhdr);
}

// Helper function to parse IP header
static __always_inline int parse_ip(void *data, void *data_end, struct flow_key *flow) {
    struct iphdr *ip = data;
    
    if ((void *)(ip + 1) > data_end) {
        return -1;
    }
    
    // Validate IP header
    if (ip->version != 4) {
        return -1;
    }
    
    flow->src_ip = ip->saddr;
    flow->dst_ip = ip->daddr;
    flow->protocol = ip->protocol;
    
    return ip->ihl * 4;
}

// Helper function to parse TCP header
static __always_inline int parse_tcp(void *data, void *data_end, struct flow_key *flow, __u32 *tcp_flags) {
    struct tcphdr *tcp = data;
    
    if ((void *)(tcp + 1) > data_end) {
        return -1;
    }
    
    flow->src_port = bpf_ntohs(tcp->source);
    flow->dst_port = bpf_ntohs(tcp->dest);
    
    if (tcp_flags) {
        *tcp_flags = 0;
        if (tcp->syn) *tcp_flags |= 0x02;
        if (tcp->ack) *tcp_flags |= 0x10;
        if (tcp->fin) *tcp_flags |= 0x01;
        if (tcp->rst) *tcp_flags |= 0x04;
        if (tcp->psh) *tcp_flags |= 0x08;
        if (tcp->urg) *tcp_flags |= 0x20;
    }
    
    return tcp->doff * 4;
}

// Helper function to parse UDP header
static __always_inline int parse_udp(void *data, void *data_end, struct flow_key *flow) {
    struct udphdr *udp = data;
    
    if ((void *)(udp + 1) > data_end) {
        return -1;
    }
    
    flow->src_port = bpf_ntohs(udp->source);
    flow->dst_port = bpf_ntohs(udp->dest);
    
    return sizeof(struct udphdr);
}

// Helper function to detect HTTP traffic
static __always_inline int detect_http(void *data, void *data_end, char *method, char *path, __u16 *status) {
    char *payload = (char *)data;
    int len = data_end - data;
    
    if (len < 16) {
        return 0;
    }
    
    // Check for HTTP request methods
    if (len >= 4) {
        if (bpf_memcmp(payload, "GET ", 4) == 0) {
            bpf_memcpy(method, "GET", 4);
            // Extract path (simplified)
            if (len >= 8) {
                int path_start = 4;
                int path_len = 0;
                #pragma unroll
                for (int i = path_start; i < len - 1 && i < path_start + 63; i++) {
                    if (payload[i] == ' ' || payload[i] == '\r' || payload[i] == '\n') {
                        break;
                    }
                    path[path_len++] = payload[i];
                }
            }
            return 1;
        }
        
        if (bpf_memcmp(payload, "POST", 4) == 0) {
            bpf_memcpy(method, "POST", 4);
            return 1;
        }
        
        if (bpf_memcmp(payload, "PUT ", 4) == 0) {
            bpf_memcpy(method, "PUT", 4);
            return 1;
        }
        
        if (bpf_memcmp(payload, "DELE", 4) == 0) {
            bpf_memcpy(method, "DELETE", 6);
            return 1;
        }
    }
    
    // Check for HTTP response
    if (len >= 12) {
        if (bpf_memcmp(payload, "HTTP/1.", 7) == 0) {
            // Extract status code
            if (len >= 12 && payload[8] == ' ') {
                *status = (payload[9] - '0') * 100 + (payload[10] - '0') * 10 + (payload[11] - '0');
                return 2; // HTTP response
            }
        }
    }
    
    return 0;
}

// Helper function to update flow statistics
static __always_inline void update_flow_stats(struct flow_key *flow, __u16 packet_size, __u32 tcp_flags, __u8 is_http) {
    struct flow_stats *stats = bpf_map_lookup_elem(&flow_table, flow);
    __u64 now = bpf_ktime_get_ns();
    
    if (!stats) {
        // New flow
        struct flow_stats new_stats = {};
        new_stats.packets = 1;
        new_stats.bytes = packet_size;
        new_stats.first_seen = now;
        new_stats.last_seen = now;
        new_stats.tcp_flags = tcp_flags;
        new_stats.flow_state = 0; // new
        
        if (is_http == 1) {
            new_stats.http_requests = 1;
        } else if (is_http == 2) {
            new_stats.http_responses = 1;
        }
        
        bpf_map_update_elem(&flow_table, flow, &new_stats, BPF_ANY);
    } else {
        // Update existing flow
        stats->packets++;
        stats->bytes += packet_size;
        stats->last_seen = now;
        stats->tcp_flags |= tcp_flags;
        
        if (is_http == 1) {
            stats->http_requests++;
        } else if (is_http == 2) {
            stats->http_responses++;
        }
        
        // Update flow state based on TCP flags
        if (tcp_flags & 0x02) { // SYN
            stats->flow_state = 0; // new
        } else if (tcp_flags & 0x10) { // ACK
            stats->flow_state = 1; // established
        } else if (tcp_flags & 0x01) { // FIN
            stats->flow_state = 2; // closing
        } else if (tcp_flags & 0x04) { // RST
            stats->flow_state = 3; // closed
        }
    }
}

// Helper function to check configuration
static __always_inline __u32 get_config(__u32 key, __u32 default_value) {
    __u32 *value = bpf_map_lookup_elem(&xdp_config, &key);
    return value ? *value : default_value;
}

// Main XDP program
SEC("xdp")
int xdp_packet_tracer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 start_time = bpf_ktime_get_ns();
    
    // Basic packet validation
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }
    
    // Check if packet capture is enabled
    if (!get_config(CONFIG_ENABLE_PACKET_CAPTURE, 1)) {
        return XDP_PASS;
    }
    
    // Update packet counters
    __u32 key = 0;
    __u64 *packet_count = bpf_map_lookup_elem(&packet_counter, &key);
    if (packet_count) {
        __sync_fetch_and_add(packet_count, 1);
    }
    
    __u64 packet_size = data_end - data;
    __u64 *byte_count = bpf_map_lookup_elem(&byte_counter, &key);
    if (byte_count) {
        __sync_fetch_and_add(byte_count, packet_size);
    }
    
    // Parse Ethernet header
    __u16 eth_proto;
    int eth_len = parse_ethernet(data, data_end, &eth_proto);
    if (eth_len < 0) {
        return XDP_PASS;
    }
    
    // Only process IPv4 for now
    if (eth_proto != ETH_P_IP) {
        return XDP_PASS;
    }
    
    // Parse IP header
    struct flow_key flow = {};
    int ip_len = parse_ip(data + eth_len, data_end, &flow);
    if (ip_len < 0) {
        return XDP_PASS;
    }
    
    // Parse transport layer
    __u32 tcp_flags = 0;
    int transport_len = 0;
    void *payload = data + eth_len + ip_len;
    
    if (flow.protocol == IPPROTO_TCP) {
        transport_len = parse_tcp(data + eth_len + ip_len, data_end, &flow, &tcp_flags);
        if (transport_len < 0) {
            return XDP_PASS;
        }
        payload += transport_len;
    } else if (flow.protocol == IPPROTO_UDP) {
        transport_len = parse_udp(data + eth_len + ip_len, data_end, &flow);
        if (transport_len < 0) {
            return XDP_PASS;
        }
        payload += transport_len;
    } else {
        return XDP_PASS;
    }
    
    // HTTP detection
    __u8 is_http = 0;
    char http_method[8] = {};
    char http_path[64] = {};
    __u16 http_status = 0;
    
    if (get_config(CONFIG_ENABLE_HTTP_DETECTION, 1) && payload < data_end) {
        is_http = detect_http(payload, data_end, http_method, http_path, &http_status);
    }
    
    // Update flow tracking
    if (get_config(CONFIG_ENABLE_FLOW_TRACKING, 1)) {
        update_flow_stats(&flow, packet_size, tcp_flags, is_http);
    }
    
    // Create XDP event for interesting packets
    if (is_http || tcp_flags & 0x02 || tcp_flags & 0x01) { // HTTP or SYN/FIN
        struct xdp_event *event = bpf_ringbuf_reserve(&xdp_events, sizeof(*event), 0);
        if (event) {
            bpf_memset(event, 0, sizeof(*event));
            
            event->timestamp = start_time;
            event->ifindex = ctx->ingress_ifindex;
            event->rx_queue = ctx->rx_queue_index;
            event->packet_size = packet_size;
            event->payload_offset = payload - data;
            event->protocol = flow.protocol;
            event->direction = 0; // ingress
            event->action = XDP_PASS;
            
            // Copy flow information
            bpf_memcpy(&event->flow, &flow, sizeof(flow));
            
            // Copy HTTP information
            event->is_http = is_http;
            if (is_http == 1) {
                bpf_memcpy(event->http_method, http_method, sizeof(http_method));
                bpf_memcpy(event->http_path, http_path, sizeof(http_path));
            } else if (is_http == 2) {
                event->http_status = http_status;
            }
            
            // Performance metrics
            event->processing_time_ns = bpf_ktime_get_ns() - start_time;
            event->cpu_id = bpf_get_smp_processor_id();
            
            // Copy packet data for analysis (limited to 256 bytes)
            int copy_len = packet_size > 256 ? 256 : packet_size;
            if (data + copy_len <= data_end) {
                #pragma unroll
                for (int i = 0; i < copy_len && i < 256; i++) {
                    if (data + i < data_end) {
                        event->packet_data[i] = *((char *)data + i);
                    }
                }
            }
            
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    return XDP_PASS;
}

// XDP program for egress traffic (TC-based)
SEC("tc")
int tc_egress_tracer(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u64 start_time = bpf_ktime_get_ns();
    
    // Basic validation
    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK;
    }
    
    // Parse headers similar to XDP program
    __u16 eth_proto;
    int eth_len = parse_ethernet(data, data_end, &eth_proto);
    if (eth_len < 0 || eth_proto != ETH_P_IP) {
        return TC_ACT_OK;
    }
    
    struct flow_key flow = {};
    flow.direction = 1; // egress
    
    int ip_len = parse_ip(data + eth_len, data_end, &flow);
    if (ip_len < 0) {
        return TC_ACT_OK;
    }
    
    // Parse transport layer and detect HTTP
    __u32 tcp_flags = 0;
    int transport_len = 0;
    void *payload = data + eth_len + ip_len;
    
    if (flow.protocol == IPPROTO_TCP) {
        transport_len = parse_tcp(data + eth_len + ip_len, data_end, &flow, &tcp_flags);
        payload += transport_len;
    } else if (flow.protocol == IPPROTO_UDP) {
        transport_len = parse_udp(data + eth_len + ip_len, data_end, &flow);
        payload += transport_len;
    }
    
    // HTTP detection for egress
    __u8 is_http = 0;
    char http_method[8] = {};
    __u16 http_status = 0;
    
    if (payload < data_end) {
        is_http = detect_http(payload, data_end, http_method, NULL, &http_status);
    }
    
    // Update flow stats for egress
    if (get_config(CONFIG_ENABLE_FLOW_TRACKING, 1)) {
        update_flow_stats(&flow, skb->len, tcp_flags, is_http);
    }
    
    // Create event for interesting egress packets
    if (is_http) {
        struct xdp_event *event = bpf_ringbuf_reserve(&xdp_events, sizeof(*event), 0);
        if (event) {
            bpf_memset(event, 0, sizeof(*event));
            
            event->timestamp = start_time;
            event->ifindex = skb->ifindex;
            event->packet_size = skb->len;
            event->protocol = flow.protocol;
            event->direction = 1; // egress
            event->action = TC_ACT_OK;
            
            bpf_memcpy(&event->flow, &flow, sizeof(flow));
            
            event->is_http = is_http;
            if (is_http == 1) {
                bpf_memcpy(event->http_method, http_method, sizeof(http_method));
            } else if (is_http == 2) {
                event->http_status = http_status;
            }
            
            event->processing_time_ns = bpf_ktime_get_ns() - start_time;
            event->cpu_id = bpf_get_smp_processor_id();
            
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
