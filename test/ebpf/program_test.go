package ebpf

import (
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Test eBPF program loading and basic functionality
func TestEBPFProgramLoading(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("eBPF tests require root privileges")
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("Failed to remove memory limit: %v", err)
	}

	// Load the compiled eBPF object
	spec, err := ebpf.LoadCollectionSpec("../../http_tracer.o")
	if err != nil {
		t.Fatalf("Failed to load eBPF spec: %v", err)
	}

	// Create collection from spec
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Verify that all expected programs are loaded
	expectedPrograms := []string{
		"trace_accept",
		"trace_read", 
		"trace_connect",
	}

	for _, progName := range expectedPrograms {
		if _, exists := coll.Programs[progName]; !exists {
			t.Errorf("Expected program '%s' not found in collection", progName)
		}
	}

	// Verify that all expected maps are created
	expectedMaps := []string{
		"events",
		"request_contexts",
		"connection_map",
		"request_id_counter",
	}

	for _, mapName := range expectedMaps {
		if _, exists := coll.Maps[mapName]; !exists {
			t.Errorf("Expected map '%s' not found in collection", mapName)
		}
	}
}

// Test eBPF map operations
func TestEBPFMapOperations(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("eBPF tests require root privileges")
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("Failed to remove memory limit: %v", err)
	}

	// Load the compiled eBPF object
	spec, err := ebpf.LoadCollectionSpec("../../http_tracer.o")
	if err != nil {
		t.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Test request_id_counter map
	counterMap := coll.Maps["request_id_counter"]
	if counterMap == nil {
		t.Fatal("request_id_counter map not found")
	}

	// Test writing to and reading from the counter map
	key := uint32(0)
	value := uint64(1)

	err = counterMap.Put(key, value)
	if err != nil {
		t.Fatalf("Failed to put value in counter map: %v", err)
	}

	var readValue uint64
	err = counterMap.Lookup(key, &readValue)
	if err != nil {
		t.Fatalf("Failed to lookup value in counter map: %v", err)
	}

	if readValue != value {
		t.Errorf("Expected counter value %d, got %d", value, readValue)
	}
}

// Test eBPF program attachment (without actually attaching to avoid system impact)
func TestEBPFProgramAttachment(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("eBPF tests require root privileges")
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("Failed to remove memory limit: %v", err)
	}

	// Load the compiled eBPF object
	spec, err := ebpf.LoadCollectionSpec("../../http_tracer.o")
	if err != nil {
		t.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Test that we can create tracepoint links (but don't attach them)
	tracepointTests := []struct {
		group string
		name  string
		prog  string
	}{
		{"syscalls", "sys_enter_accept", "trace_accept"},
		{"syscalls", "sys_enter_read", "trace_read"},
		{"syscalls", "sys_enter_connect", "trace_connect"},
	}

	for _, tt := range tracepointTests {
		t.Run(tt.group+"/"+tt.name, func(t *testing.T) {
			prog := coll.Programs[tt.prog]
			if prog == nil {
				t.Fatalf("Program %s not found", tt.prog)
			}

			// Create the link but don't attach it
			l, err := link.Tracepoint(tt.group, tt.name, prog, nil)
			if err != nil {
				t.Logf("Warning: Could not create tracepoint link for %s/%s: %v", tt.group, tt.name, err)
				t.Logf("This may be expected if the tracepoint doesn't exist on this system")
				return
			}
			
			// Immediately close the link to avoid system impact
			l.Close()
			t.Logf("Successfully created and closed tracepoint link for %s/%s", tt.group, tt.name)
		})
	}
}

// Test eBPF program verification
func TestEBPFProgramVerification(t *testing.T) {
	// This test checks that the eBPF programs pass the kernel verifier
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("eBPF tests require root privileges")
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("Failed to remove memory limit: %v", err)
	}

	// Load the compiled eBPF object
	spec, err := ebpf.LoadCollectionSpec("../../http_tracer.o")
	if err != nil {
		t.Fatalf("Failed to load eBPF spec: %v", err)
	}

	// Try to create each program individually to test verification
	for progName, progSpec := range spec.Programs {
		t.Run("Program_"+progName, func(t *testing.T) {
			prog, err := ebpf.NewProgram(progSpec)
			if err != nil {
				t.Errorf("Program %s failed verification: %v", progName, err)
				return
			}
			defer prog.Close()
			
			t.Logf("Program %s passed verification", progName)
		})
	}
}

// Test eBPF map specifications
func TestEBPFMapSpecs(t *testing.T) {
	// Load the compiled eBPF object
	spec, err := ebpf.LoadCollectionSpec("../../http_tracer.o")
	if err != nil {
		t.Fatalf("Failed to load eBPF spec: %v", err)
	}

	// Test map specifications
	mapTests := []struct {
		name        string
		expectedType ebpf.MapType
		maxEntries  uint32
	}{
		{"events", ebpf.RingBuf, 0}, // Ring buffer doesn't use MaxEntries
		{"request_contexts", ebpf.Hash, 1024},
		{"connection_map", ebpf.Hash, 1024},
		{"request_id_counter", ebpf.Array, 1},
	}

	for _, mt := range mapTests {
		t.Run("Map_"+mt.name, func(t *testing.T) {
			mapSpec, exists := spec.Maps[mt.name]
			if !exists {
				t.Fatalf("Map %s not found in spec", mt.name)
			}

			if mapSpec.Type != mt.expectedType {
				t.Errorf("Map %s: expected type %v, got %v", mt.name, mt.expectedType, mapSpec.Type)
			}

			if mt.expectedType != ebpf.RingBuf && mapSpec.MaxEntries != mt.maxEntries {
				t.Errorf("Map %s: expected max entries %d, got %d", mt.name, mt.maxEntries, mapSpec.MaxEntries)
			}
		})
	}
}

// Benchmark eBPF program loading
func BenchmarkEBPFProgramLoading(b *testing.B) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		b.Skip("eBPF tests require root privileges")
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatalf("Failed to remove memory limit: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		spec, err := ebpf.LoadCollectionSpec("../../http_tracer.o")
		if err != nil {
			b.Fatalf("Failed to load eBPF spec: %v", err)
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			b.Fatalf("Failed to create eBPF collection: %v", err)
		}
		coll.Close()
	}
}

// Test eBPF program with timeout to ensure it doesn't hang
func TestEBPFProgramTimeout(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("eBPF tests require root privileges")
	}

	done := make(chan bool, 1)
	
	go func() {
		// Remove memory limit for eBPF
		if err := rlimit.RemoveMemlock(); err != nil {
			t.Errorf("Failed to remove memory limit: %v", err)
			done <- false
			return
		}

		// Load the compiled eBPF object
		spec, err := ebpf.LoadCollectionSpec("../../http_tracer.o")
		if err != nil {
			t.Errorf("Failed to load eBPF spec: %v", err)
			done <- false
			return
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			t.Errorf("Failed to create eBPF collection: %v", err)
			done <- false
			return
		}
		coll.Close()
		done <- true
	}()

	select {
	case success := <-done:
		if !success {
			t.Fatal("eBPF program loading failed")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("eBPF program loading timed out after 30 seconds")
	}
}
