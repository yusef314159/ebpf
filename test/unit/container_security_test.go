package unit

import (
	"context"
	"testing"
	"time"

	"ebpf-tracing/pkg/container"
	"ebpf-tracing/pkg/load"
	"ebpf-tracing/pkg/security"
)

// TestContainerManagerCreation tests container manager creation
func TestContainerManagerCreation(t *testing.T) {
	config := container.DefaultContainerConfig()
	if config == nil {
		t.Fatal("Expected container config to be created")
	}

	manager := container.NewContainerManager(config)
	if manager == nil {
		t.Fatal("Expected container manager to be created")
	}

	if manager.IsRunning() {
		t.Error("Expected container manager to not be running initially")
	}

	// Test configuration
	if !config.EnableContainerDiscovery {
		t.Error("Expected container discovery to be enabled by default")
	}

	if !config.EnableKubernetesIntegration {
		t.Error("Expected Kubernetes integration to be enabled by default")
	}

	if !config.EnableNamespaceIsolation {
		t.Error("Expected namespace isolation to be enabled by default")
	}

	if !config.EnableServiceMeshSupport {
		t.Error("Expected service mesh support to be enabled by default")
	}

	if config.DiscoveryInterval != 30*time.Second {
		t.Errorf("Expected discovery interval to be 30s, got %v", config.DiscoveryInterval)
	}

	if !config.MetadataCollection {
		t.Error("Expected metadata collection to be enabled by default")
	}

	if !config.ResourceMonitoring {
		t.Error("Expected resource monitoring to be enabled by default")
	}

	t.Logf("Container manager created successfully with config: %+v", config)
}

// TestContainerManagerLifecycle tests container manager lifecycle
func TestContainerManagerLifecycle(t *testing.T) {
	config := container.DefaultContainerConfig()
	// Disable actual discovery for unit test
	config.EnableContainerDiscovery = false
	config.EnableKubernetesIntegration = false
	
	manager := container.NewContainerManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test start
	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start container manager: %v", err)
	}

	if !manager.IsRunning() {
		t.Error("Expected container manager to be running after start")
	}

	// Test stats
	stats := manager.GetStats()
	if stats == nil {
		t.Error("Expected stats to be non-nil")
	}

	if stats["containers_discovered"] == nil {
		t.Error("Expected containers_discovered stat to be present")
	}

	// Test stop
	err = manager.Stop()
	if err != nil {
		t.Fatalf("Failed to stop container manager: %v", err)
	}

	if manager.IsRunning() {
		t.Error("Expected container manager to not be running after stop")
	}

	t.Logf("Container manager lifecycle test completed successfully")
}

// TestContainerDiscovery tests container discovery functionality
func TestContainerDiscovery(t *testing.T) {
	config := container.DefaultContainerConfig()
	config.EnableKubernetesIntegration = false // Disable K8s for unit test
	
	manager := container.NewContainerManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start container manager: %v", err)
	}
	defer manager.Stop()

	// Give some time for discovery
	time.Sleep(100 * time.Millisecond)

	// Test container listing
	containers := manager.ListContainers()
	if containers == nil {
		t.Error("Expected containers list to be non-nil")
	}

	// Test pod listing
	pods := manager.ListPods()
	if pods == nil {
		t.Error("Expected pods list to be non-nil")
	}

	// Test service listing
	services := manager.ListServices()
	if services == nil {
		t.Error("Expected services list to be non-nil")
	}

	t.Logf("Container discovery test completed successfully")
}

// TestLoadManagerCreation tests load manager creation
func TestLoadManagerCreation(t *testing.T) {
	config := load.DefaultLoadConfig()
	if config == nil {
		t.Fatal("Expected load config to be created")
	}

	manager := load.NewLoadManager(config)
	if manager == nil {
		t.Fatal("Expected load manager to be created")
	}

	if manager.IsRunning() {
		t.Error("Expected load manager to not be running initially")
	}

	// Test configuration
	if !config.EnableAdaptiveFiltering {
		t.Error("Expected adaptive filtering to be enabled by default")
	}

	if !config.EnableKernelFiltering {
		t.Error("Expected kernel filtering to be enabled by default")
	}

	if !config.EnableIntelligentSampling {
		t.Error("Expected intelligent sampling to be enabled by default")
	}

	if !config.EnableLoadBalancing {
		t.Error("Expected load balancing to be enabled by default")
	}

	if config.MaxEventsPerSecond != 100000 {
		t.Errorf("Expected max events per second to be 100000, got %d", config.MaxEventsPerSecond)
	}

	if config.MinSamplingRate != 0.01 {
		t.Errorf("Expected min sampling rate to be 0.01, got %f", config.MinSamplingRate)
	}

	if config.MaxSamplingRate != 1.0 {
		t.Errorf("Expected max sampling rate to be 1.0, got %f", config.MaxSamplingRate)
	}

	t.Logf("Load manager created successfully with config: %+v", config)
}

// TestLoadManagerLifecycle tests load manager lifecycle
func TestLoadManagerLifecycle(t *testing.T) {
	config := load.DefaultLoadConfig()
	// Disable actual eBPF for unit test
	config.EnableKernelFiltering = false
	
	manager := load.NewLoadManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test start
	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start load manager: %v", err)
	}

	if !manager.IsRunning() {
		t.Error("Expected load manager to be running after start")
	}

	// Test sampling decisions
	shouldSample1 := manager.ShouldSample("test_event", map[string]string{"priority": "high"})
	if !shouldSample1 {
		t.Log("High priority event was not sampled (this may be expected based on current rate)")
	}

	shouldSample2 := manager.ShouldSample("debug_event", map[string]string{"priority": "low"})
	t.Logf("Debug event sampling decision: %v", shouldSample2)

	// Record some events
	manager.RecordEvent()
	manager.RecordEvent()
	manager.RecordDrop()

	// Test stats
	stats := manager.GetStats()
	if stats == nil {
		t.Error("Expected stats to be non-nil")
	}

	if stats.ProcessedEvents < 2 {
		t.Errorf("Expected at least 2 processed events, got %d", stats.ProcessedEvents)
	}

	if stats.DroppedEvents < 1 {
		t.Errorf("Expected at least 1 dropped event, got %d", stats.DroppedEvents)
	}

	// Test stop
	err = manager.Stop()
	if err != nil {
		t.Fatalf("Failed to stop load manager: %v", err)
	}

	if manager.IsRunning() {
		t.Error("Expected load manager to not be running after stop")
	}

	t.Logf("Load manager lifecycle test completed successfully")
}

// TestLSMManagerCreation tests LSM manager creation
func TestLSMManagerCreation(t *testing.T) {
	config := security.DefaultLSMConfig()
	if config == nil {
		t.Fatal("Expected LSM config to be created")
	}

	manager := security.NewLSMManager(config)
	if manager == nil {
		t.Fatal("Expected LSM manager to be created")
	}

	if manager.IsRunning() {
		t.Error("Expected LSM manager to not be running initially")
	}

	// Test configuration
	if !config.EnableSELinux {
		t.Error("Expected SELinux to be enabled by default")
	}

	if !config.EnableAppArmor {
		t.Error("Expected AppArmor to be enabled by default")
	}

	if !config.EnableSeccomp {
		t.Error("Expected seccomp to be enabled by default")
	}

	if !config.EnableCapabilities {
		t.Error("Expected capabilities to be enabled by default")
	}

	if !config.EnableSandboxing {
		t.Error("Expected sandboxing to be enabled by default")
	}

	if config.SELinuxPolicy != "targeted" {
		t.Errorf("Expected SELinux policy to be 'targeted', got %s", config.SELinuxPolicy)
	}

	if config.ApparmorProfile != "ebpf-tracer" {
		t.Errorf("Expected AppArmor profile to be 'ebpf-tracer', got %s", config.ApparmorProfile)
	}

	if len(config.AllowedCapabilities) == 0 {
		t.Error("Expected some allowed capabilities to be configured")
	}

	t.Logf("LSM manager created successfully with config: %+v", config)
}

// TestLSMManagerLifecycle tests LSM manager lifecycle
func TestLSMManagerLifecycle(t *testing.T) {
	config := security.DefaultLSMConfig()
	// Disable actual LSM operations for unit test
	config.EnableSELinux = false
	config.EnableAppArmor = false
	config.EnableSandboxing = false
	
	manager := security.NewLSMManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test start
	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start LSM manager: %v", err)
	}

	if !manager.IsRunning() {
		t.Error("Expected LSM manager to be running after start")
	}

	// Test getting active LSMs
	activeLSMs := manager.GetActiveLSMs()
	if activeLSMs == nil {
		t.Error("Expected active LSMs list to be non-nil")
	}

	// Test stats
	stats := manager.GetStats()
	if stats == nil {
		t.Error("Expected stats to be non-nil")
	}

	if stats["active_lsms"] == nil {
		t.Error("Expected active_lsms stat to be present")
	}

	// Test stop
	err = manager.Stop()
	if err != nil {
		t.Fatalf("Failed to stop LSM manager: %v", err)
	}

	if manager.IsRunning() {
		t.Error("Expected LSM manager to not be running after stop")
	}

	t.Logf("LSM manager lifecycle test completed successfully")
}

// TestLoadSampling tests load-based sampling functionality
func TestLoadSampling(t *testing.T) {
	config := load.DefaultLoadConfig()
	config.EnableKernelFiltering = false
	config.MaxSamplingRate = 1.0
	config.MinSamplingRate = 0.1
	
	manager := load.NewLoadManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start load manager: %v", err)
	}
	defer manager.Stop()

	// Test different event types
	testCases := []struct {
		eventType string
		metadata  map[string]string
		expectSample bool
	}{
		{"error_event", map[string]string{"level": "error"}, true},
		{"info_event", map[string]string{"level": "info"}, true},
		{"debug_event", map[string]string{"level": "debug"}, true},
	}

	for _, tc := range testCases {
		result := manager.ShouldSample(tc.eventType, tc.metadata)
		t.Logf("Event type %s sampling result: %v", tc.eventType, result)
		
		// Record the event for statistics
		if result {
			manager.RecordEvent()
		} else {
			manager.RecordDrop()
		}
	}

	// Check final stats
	stats := manager.GetStats()
	t.Logf("Final load manager stats: processed=%d, dropped=%d, rate=%f", 
		stats.ProcessedEvents, stats.DroppedEvents, stats.CurrentSamplingRate)

	t.Logf("Load sampling test completed successfully")
}

// TestContainerMetadata tests container metadata collection
func TestContainerMetadata(t *testing.T) {
	config := container.DefaultContainerConfig()
	config.EnableKubernetesIntegration = false
	config.MetadataCollection = true
	
	manager := container.NewContainerManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start container manager: %v", err)
	}
	defer manager.Stop()

	// Test container lookup by PID (simulated)
	container, found := manager.GetContainerByPID(1)
	if found {
		t.Logf("Found container for PID 1: %+v", container)
	} else {
		t.Log("No container found for PID 1 (expected in unit test)")
	}

	// Test namespace lookup
	namespace, found := manager.GetNamespace("test-ns")
	if found {
		t.Logf("Found namespace: %+v", namespace)
	} else {
		t.Log("No namespace found for test-ns (expected in unit test)")
	}

	t.Logf("Container metadata test completed successfully")
}

// TestSecurityIntegration tests security integration
func TestSecurityIntegration(t *testing.T) {
	// Test container manager with security
	containerConfig := container.DefaultContainerConfig()
	containerConfig.EnableKubernetesIntegration = false
	containerManager := container.NewContainerManager(containerConfig)

	// Test LSM manager
	lsmConfig := security.DefaultLSMConfig()
	lsmConfig.EnableSELinux = false
	lsmConfig.EnableAppArmor = false
	lsmConfig.EnableSandboxing = false
	lsmManager := security.NewLSMManager(lsmConfig)

	// Test load manager
	loadConfig := load.DefaultLoadConfig()
	loadConfig.EnableKernelFiltering = false
	loadManager := load.NewLoadManager(loadConfig)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Start all managers
	if err := containerManager.Start(ctx); err != nil {
		t.Fatalf("Failed to start container manager: %v", err)
	}
	defer containerManager.Stop()

	if err := lsmManager.Start(ctx); err != nil {
		t.Fatalf("Failed to start LSM manager: %v", err)
	}
	defer lsmManager.Stop()

	if err := loadManager.Start(ctx); err != nil {
		t.Fatalf("Failed to start load manager: %v", err)
	}
	defer loadManager.Stop()

	// Verify all managers are running
	if !containerManager.IsRunning() {
		t.Error("Expected container manager to be running")
	}

	if !lsmManager.IsRunning() {
		t.Error("Expected LSM manager to be running")
	}

	if !loadManager.IsRunning() {
		t.Error("Expected load manager to be running")
	}

	// Test integrated functionality
	containerStats := containerManager.GetStats()
	lsmStats := lsmManager.GetStats()
	loadStats := loadManager.GetStats()

	t.Logf("Container stats: %+v", containerStats)
	t.Logf("LSM stats: %+v", lsmStats)
	t.Logf("Load stats: processed=%d, dropped=%d", loadStats.ProcessedEvents, loadStats.DroppedEvents)

	t.Logf("Security integration test completed successfully")
}
