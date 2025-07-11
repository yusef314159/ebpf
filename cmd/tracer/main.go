package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Event structure matching the C struct
type Event struct {
	Timestamp  uint64     `json:"timestamp"`
	RequestID  uint64     `json:"request_id"`
	PID        uint32     `json:"pid"`
	TID        uint32     `json:"tid"`
	SrcIP      uint32     `json:"src_ip"`
	DstIP      uint32     `json:"dst_ip"`
	SrcPort    uint16     `json:"src_port"`
	DstPort    uint16     `json:"dst_port"`
	Comm       [16]byte   `json:"-"`
	Method     [8]byte    `json:"-"`
	Path       [128]byte  `json:"-"`
	PayloadLen uint32     `json:"payload_len"`
	Payload    [256]byte  `json:"-"`
	EventType  uint8      `json:"event_type"`
	Protocol   uint8      `json:"protocol"`
}

// JSON-friendly event structure
type JSONEvent struct {
	Timestamp   string `json:"timestamp"`
	RequestID   uint64 `json:"request_id,omitempty"`
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	Comm        string `json:"comm"`
	Method      string `json:"method,omitempty"`
	Path        string `json:"path,omitempty"`
	PayloadLen  uint32 `json:"payload_len"`
	Payload     string `json:"payload,omitempty"`
	EventType   string `json:"event_type"`
	EventTypeID uint8  `json:"event_type_id"`
	Protocol    string `json:"protocol,omitempty"`
}

func main() {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled eBPF program
	spec, err := ebpf.LoadCollectionSpec("http_tracer.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Attach tracepoints
	links := make([]link.Link, 0)
	
	// Accept enter
	l1, err := link.Tracepoint(link.TracepointOptions{
		Group:   "syscalls",
		Name:    "sys_enter_accept",
		Program: coll.Programs["trace_accept_enter"],
	})
	if err != nil {
		log.Fatalf("Failed to attach accept enter tracepoint: %v", err)
	}
	links = append(links, l1)

	// Accept exit
	l2, err := link.Tracepoint(link.TracepointOptions{
		Group:   "syscalls",
		Name:    "sys_exit_accept",
		Program: coll.Programs["trace_accept_exit"],
	})
	if err != nil {
		log.Fatalf("Failed to attach accept exit tracepoint: %v", err)
	}
	links = append(links, l2)

	// Read enter
	l3, err := link.Tracepoint(link.TracepointOptions{
		Group:   "syscalls",
		Name:    "sys_enter_read",
		Program: coll.Programs["trace_read_enter"],
	})
	if err != nil {
		log.Fatalf("Failed to attach read enter tracepoint: %v", err)
	}
	links = append(links, l3)

	// Connect enter
	l4, err := link.Tracepoint(link.TracepointOptions{
		Group:   "syscalls",
		Name:    "sys_enter_connect",
		Program: coll.Programs["trace_connect_enter"],
	})
	if err != nil {
		log.Fatalf("Failed to attach connect enter tracepoint: %v", err)
	}
	links = append(links, l4)

	// Cleanup on exit
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	// Open ring buffer
	rd, err := ringbuf.NewReader(coll.Maps["rb"])
	if err != nil {
		log.Fatalf("Failed to create ring buffer reader: %v", err)
	}
	defer rd.Close()

	log.Println("eBPF HTTP tracer started. Press Ctrl+C to exit.")

	// Handle signals
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("Received signal, shutting down...")
		cancel()
	}()

	// Process events
	for {
		select {
		case <-ctx.Done():
			return
		default:
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			if len(record.RawSample) < int(unsafe.Sizeof(Event{})) {
				continue
			}

			// Parse event
			var event Event
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			// Convert to JSON-friendly format
			jsonEvent := convertToJSONEvent(event)

			// Log different event types based on configuration
			shouldLog := false
			switch jsonEvent.EventTypeID {
			case 1: // read events - log if HTTP request detected
				shouldLog = jsonEvent.Method != ""
			case 2: // connect events - log if correlated with HTTP request
				shouldLog = jsonEvent.RequestID != 0
			default:
				shouldLog = false
			}

			if shouldLog {
				jsonData, err := json.Marshal(jsonEvent)
				if err != nil {
					log.Printf("Error marshaling JSON: %v", err)
					continue
				}
				fmt.Println(string(jsonData))
			}
		}
	}
}

func convertToJSONEvent(event Event) JSONEvent {
	jsonEvent := JSONEvent{
		Timestamp:   time.Unix(0, int64(event.Timestamp)).Format(time.RFC3339Nano),
		RequestID:   event.RequestID,
		PID:         event.PID,
		TID:         event.TID,
		SrcIP:       ipToString(event.SrcIP),
		DstIP:       ipToString(event.DstIP),
		SrcPort:     event.SrcPort,
		DstPort:     event.DstPort,
		Comm:        nullTerminatedString(event.Comm[:]),
		Method:      nullTerminatedString(event.Method[:]),
		Path:        nullTerminatedString(event.Path[:]),
		PayloadLen:  event.PayloadLen,
		EventTypeID: event.EventType,
	}

	// Set event type string
	switch event.EventType {
	case 0:
		jsonEvent.EventType = "accept"
	case 1:
		jsonEvent.EventType = "read"
	case 2:
		jsonEvent.EventType = "connect"
	case 3:
		jsonEvent.EventType = "write"
	default:
		jsonEvent.EventType = "unknown"
	}

	// Set protocol string
	switch event.Protocol {
	case 6:
		jsonEvent.Protocol = "TCP"
	case 17:
		jsonEvent.Protocol = "UDP"
	default:
		jsonEvent.Protocol = ""
	}

	// Add payload if it contains printable data
	if event.PayloadLen > 0 {
		payload := event.Payload[:event.PayloadLen]
		if isPrintable(payload) {
			jsonEvent.Payload = string(payload)
		}
	}

	return jsonEvent
}

func nullTerminatedString(data []byte) string {
	n := bytes.IndexByte(data, 0)
	if n == -1 {
		return string(data)
	}
	return string(data[:n])
}

func ipToString(ip uint32) string {
	if ip == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
