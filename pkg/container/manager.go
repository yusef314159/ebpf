package container

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ContainerManager provides container-native tracing capabilities
type ContainerManager struct {
	config           *ContainerConfig
	containers       map[string]*ContainerInfo
	namespaces       map[string]*NamespaceInfo
	pods             map[string]*PodInfo
	services         map[string]*ServiceInfo
	containerRuntime ContainerRuntime
	k8sClient        *KubernetesClient
	mutex            sync.RWMutex
	running          bool
	stopChan         chan struct{}
}

// ContainerConfig holds container manager configuration
type ContainerConfig struct {
	EnableContainerDiscovery bool          `json:"enable_container_discovery" yaml:"enable_container_discovery"`
	EnableKubernetesIntegration bool       `json:"enable_kubernetes_integration" yaml:"enable_kubernetes_integration"`
	EnableNamespaceIsolation bool          `json:"enable_namespace_isolation" yaml:"enable_namespace_isolation"`
	EnableServiceMeshSupport bool          `json:"enable_service_mesh_support" yaml:"enable_service_mesh_support"`
	ContainerRuntimes        []string      `json:"container_runtimes" yaml:"container_runtimes"`
	KubeconfigPath           string        `json:"kubeconfig_path" yaml:"kubeconfig_path"`
	NamespaceFilters         []string      `json:"namespace_filters" yaml:"namespace_filters"`
	PodFilters               []string      `json:"pod_filters" yaml:"pod_filters"`
	ServiceFilters           []string      `json:"service_filters" yaml:"service_filters"`
	DiscoveryInterval        time.Duration `json:"discovery_interval" yaml:"discovery_interval"`
	MetadataCollection       bool          `json:"metadata_collection" yaml:"metadata_collection"`
	ResourceMonitoring       bool          `json:"resource_monitoring" yaml:"resource_monitoring"`
}

// ContainerInfo holds information about a container
type ContainerInfo struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Image           string            `json:"image"`
	ImageID         string            `json:"image_id"`
	Runtime         string            `json:"runtime"`
	State           string            `json:"state"`
	Status          string            `json:"status"`
	PID             int               `json:"pid"`
	NetworkMode     string            `json:"network_mode"`
	IPAddress       string            `json:"ip_address"`
	Ports           []PortMapping     `json:"ports"`
	Volumes         []VolumeMount     `json:"volumes"`
	Environment     map[string]string `json:"environment"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
	CreatedAt       time.Time         `json:"created_at"`
	StartedAt       time.Time         `json:"started_at"`
	NamespaceID     string            `json:"namespace_id"`
	CgroupPath      string            `json:"cgroup_path"`
	RootfsPath      string            `json:"rootfs_path"`
	LogPath         string            `json:"log_path"`
	PodName         string            `json:"pod_name"`
	PodNamespace    string            `json:"pod_namespace"`
	ServiceName     string            `json:"service_name"`
	ResourceLimits  ResourceLimits    `json:"resource_limits"`
	ResourceUsage   ResourceUsage     `json:"resource_usage"`
}

// NamespaceInfo holds information about a container namespace
type NamespaceInfo struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"` // "pid", "net", "mnt", "uts", "ipc", "user"
	Path        string            `json:"path"`
	Containers  []string          `json:"containers"`
	CreatedAt   time.Time         `json:"created_at"`
	Metadata    map[string]string `json:"metadata"`
}

// PodInfo holds information about a Kubernetes pod
type PodInfo struct {
	Name         string            `json:"name"`
	Namespace    string            `json:"namespace"`
	UID          string            `json:"uid"`
	NodeName     string            `json:"node_name"`
	Phase        string            `json:"phase"`
	PodIP        string            `json:"pod_ip"`
	HostIP       string            `json:"host_ip"`
	Containers   []string          `json:"containers"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	OwnerRefs    []OwnerReference  `json:"owner_refs"`
	CreatedAt    time.Time         `json:"created_at"`
	StartedAt    time.Time         `json:"started_at"`
	ServiceAccount string          `json:"service_account"`
	QOSClass     string            `json:"qos_class"`
}

// ServiceInfo holds information about a Kubernetes service
type ServiceInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	UID         string            `json:"uid"`
	Type        string            `json:"type"`
	ClusterIP   string            `json:"cluster_ip"`
	ExternalIPs []string          `json:"external_ips"`
	Ports       []ServicePort     `json:"ports"`
	Selector    map[string]string `json:"selector"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	CreatedAt   time.Time         `json:"created_at"`
	Endpoints   []Endpoint        `json:"endpoints"`
}

// PortMapping represents a container port mapping
type PortMapping struct {
	ContainerPort int    `json:"container_port"`
	HostPort      int    `json:"host_port"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"host_ip"`
}

// VolumeMount represents a container volume mount
type VolumeMount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
}

// ResourceLimits represents container resource limits
type ResourceLimits struct {
	CPULimit    string `json:"cpu_limit"`
	MemoryLimit string `json:"memory_limit"`
	CPURequest  string `json:"cpu_request"`
	MemoryRequest string `json:"memory_request"`
}

// ResourceUsage represents current container resource usage
type ResourceUsage struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage uint64  `json:"memory_usage"`
	NetworkRx   uint64  `json:"network_rx"`
	NetworkTx   uint64  `json:"network_tx"`
	DiskRead    uint64  `json:"disk_read"`
	DiskWrite   uint64  `json:"disk_write"`
}

// OwnerReference represents a Kubernetes owner reference
type OwnerReference struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

// ServicePort represents a Kubernetes service port
type ServicePort struct {
	Name       string `json:"name"`
	Port       int    `json:"port"`
	TargetPort string `json:"target_port"`
	Protocol   string `json:"protocol"`
	NodePort   int    `json:"node_port"`
}

// Endpoint represents a Kubernetes endpoint
type Endpoint struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Ready    bool   `json:"ready"`
}

// ContainerRuntime interface for different container runtimes
type ContainerRuntime interface {
	ListContainers() ([]*ContainerInfo, error)
	GetContainer(id string) (*ContainerInfo, error)
	GetContainerLogs(id string, lines int) ([]string, error)
	GetContainerStats(id string) (*ResourceUsage, error)
}

// KubernetesClient provides Kubernetes API integration
type KubernetesClient struct {
	config     *K8sConfig
	apiServer  string
	token      string
	namespace  string
	httpClient *HTTPClient
}

// K8sConfig holds Kubernetes client configuration
type K8sConfig struct {
	APIServer     string `json:"api_server"`
	Token         string `json:"token"`
	CACert        string `json:"ca_cert"`
	Namespace     string `json:"namespace"`
	InCluster     bool   `json:"in_cluster"`
	KubeconfigPath string `json:"kubeconfig_path"`
}

// HTTPClient simplified HTTP client for K8s API
type HTTPClient struct {
	// Simplified implementation
}

// DefaultContainerConfig returns default container configuration
func DefaultContainerConfig() *ContainerConfig {
	return &ContainerConfig{
		EnableContainerDiscovery:    true,
		EnableKubernetesIntegration: true,
		EnableNamespaceIsolation:    true,
		EnableServiceMeshSupport:    true,
		ContainerRuntimes:           []string{"docker", "containerd", "cri-o"},
		KubeconfigPath:              "/root/.kube/config",
		NamespaceFilters:            []string{"default", "kube-system", "monitoring"},
		PodFilters:                  []string{},
		ServiceFilters:              []string{},
		DiscoveryInterval:           30 * time.Second,
		MetadataCollection:          true,
		ResourceMonitoring:          true,
	}
}

// NewContainerManager creates a new container manager
func NewContainerManager(config *ContainerConfig) *ContainerManager {
	cm := &ContainerManager{
		config:     config,
		containers: make(map[string]*ContainerInfo),
		namespaces: make(map[string]*NamespaceInfo),
		pods:       make(map[string]*PodInfo),
		services:   make(map[string]*ServiceInfo),
		stopChan:   make(chan struct{}),
	}

	// Initialize container runtime
	cm.containerRuntime = NewDockerRuntime() // Default to Docker

	// Initialize Kubernetes client if enabled
	if config.EnableKubernetesIntegration {
		cm.k8sClient = NewKubernetesClient(&K8sConfig{
			KubeconfigPath: config.KubeconfigPath,
			InCluster:      cm.isRunningInCluster(),
		})
	}

	return cm
}

// Start starts the container manager
func (cm *ContainerManager) Start(ctx context.Context) error {
	if cm.running {
		return fmt.Errorf("container manager already running")
	}

	// Discover existing containers
	if err := cm.discoverContainers(); err != nil {
		return fmt.Errorf("failed to discover containers: %w", err)
	}

	// Discover Kubernetes resources if enabled
	if cm.config.EnableKubernetesIntegration && cm.k8sClient != nil {
		if err := cm.discoverKubernetesResources(); err != nil {
			fmt.Printf("Warning: Failed to discover Kubernetes resources: %v\n", err)
		}
	}

	cm.running = true

	// Start discovery loops
	go cm.containerDiscoveryLoop(ctx)
	if cm.config.EnableKubernetesIntegration {
		go cm.kubernetesDiscoveryLoop(ctx)
	}
	go cm.resourceMonitoringLoop(ctx)

	return nil
}

// Stop stops the container manager
func (cm *ContainerManager) Stop() error {
	if !cm.running {
		return fmt.Errorf("container manager not running")
	}

	cm.running = false
	close(cm.stopChan)

	return nil
}

// discoverContainers discovers running containers
func (cm *ContainerManager) discoverContainers() error {
	containers, err := cm.containerRuntime.ListContainers()
	if err != nil {
		return err
	}

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	for _, container := range containers {
		cm.containers[container.ID] = container
		
		// Discover namespaces for this container
		if cm.config.EnableNamespaceIsolation {
			cm.discoverContainerNamespaces(container)
		}
	}

	return nil
}

// discoverKubernetesResources discovers Kubernetes resources
func (cm *ContainerManager) discoverKubernetesResources() error {
	// Discover pods
	pods, err := cm.k8sClient.ListPods("")
	if err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	// Discover services
	services, err := cm.k8sClient.ListServices("")
	if err != nil {
		return fmt.Errorf("failed to list services: %w", err)
	}

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	for _, pod := range pods {
		cm.pods[pod.UID] = pod
	}

	for _, service := range services {
		cm.services[service.UID] = service
	}

	return nil
}

// discoverContainerNamespaces discovers namespaces for a container
func (cm *ContainerManager) discoverContainerNamespaces(container *ContainerInfo) {
	// Discover PID namespace
	if pidNs := cm.getContainerNamespace(container.PID, "pid"); pidNs != nil {
		cm.namespaces[pidNs.ID] = pidNs
	}

	// Discover network namespace
	if netNs := cm.getContainerNamespace(container.PID, "net"); netNs != nil {
		cm.namespaces[netNs.ID] = netNs
	}

	// Discover mount namespace
	if mntNs := cm.getContainerNamespace(container.PID, "mnt"); mntNs != nil {
		cm.namespaces[mntNs.ID] = mntNs
	}
}

// getContainerNamespace gets namespace information for a container
func (cm *ContainerManager) getContainerNamespace(pid int, nsType string) *NamespaceInfo {
	nsPath := fmt.Sprintf("/proc/%d/ns/%s", pid, nsType)
	
	// Read namespace link
	link, err := os.Readlink(nsPath)
	if err != nil {
		return nil
	}

	// Extract namespace ID
	re := regexp.MustCompile(`\[(\d+)\]`)
	matches := re.FindStringSubmatch(link)
	if len(matches) < 2 {
		return nil
	}

	return &NamespaceInfo{
		ID:        matches[1],
		Type:      nsType,
		Path:      nsPath,
		CreatedAt: time.Now(),
		Metadata:  make(map[string]string),
	}
}

// containerDiscoveryLoop runs container discovery loop
func (cm *ContainerManager) containerDiscoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(cm.config.DiscoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopChan:
			return
		case <-ticker.C:
			if err := cm.discoverContainers(); err != nil {
				fmt.Printf("Container discovery error: %v\n", err)
			}
		}
	}
}

// kubernetesDiscoveryLoop runs Kubernetes discovery loop
func (cm *ContainerManager) kubernetesDiscoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(cm.config.DiscoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopChan:
			return
		case <-ticker.C:
			if err := cm.discoverKubernetesResources(); err != nil {
				fmt.Printf("Kubernetes discovery error: %v\n", err)
			}
		}
	}
}

// resourceMonitoringLoop runs resource monitoring loop
func (cm *ContainerManager) resourceMonitoringLoop(ctx context.Context) {
	if !cm.config.ResourceMonitoring {
		return
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopChan:
			return
		case <-ticker.C:
			cm.updateResourceUsage()
		}
	}
}

// updateResourceUsage updates resource usage for all containers
func (cm *ContainerManager) updateResourceUsage() {
	cm.mutex.RLock()
	containers := make([]*ContainerInfo, 0, len(cm.containers))
	for _, container := range cm.containers {
		containers = append(containers, container)
	}
	cm.mutex.RUnlock()

	for _, container := range containers {
		if stats, err := cm.containerRuntime.GetContainerStats(container.ID); err == nil {
			cm.mutex.Lock()
			if c, exists := cm.containers[container.ID]; exists {
				c.ResourceUsage = *stats
			}
			cm.mutex.Unlock()
		}
	}
}

// isRunningInCluster checks if running inside a Kubernetes cluster
func (cm *ContainerManager) isRunningInCluster() bool {
	// Check for service account token
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}
	return false
}

// GetContainer returns container information by ID
func (cm *ContainerManager) GetContainer(id string) (*ContainerInfo, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	container, exists := cm.containers[id]
	return container, exists
}

// GetContainerByPID returns container information by PID
func (cm *ContainerManager) GetContainerByPID(pid int) (*ContainerInfo, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	for _, container := range cm.containers {
		if container.PID == pid {
			return container, true
		}
	}
	return nil, false
}

// GetPod returns pod information by name and namespace
func (cm *ContainerManager) GetPod(name, namespace string) (*PodInfo, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	for _, pod := range cm.pods {
		if pod.Name == name && pod.Namespace == namespace {
			return pod, true
		}
	}
	return nil, false
}

// GetService returns service information by name and namespace
func (cm *ContainerManager) GetService(name, namespace string) (*ServiceInfo, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	for _, service := range cm.services {
		if service.Name == name && service.Namespace == namespace {
			return service, true
		}
	}
	return nil, false
}

// GetNamespace returns namespace information by ID
func (cm *ContainerManager) GetNamespace(id string) (*NamespaceInfo, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	namespace, exists := cm.namespaces[id]
	return namespace, exists
}

// ListContainers returns all discovered containers
func (cm *ContainerManager) ListContainers() []*ContainerInfo {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	containers := make([]*ContainerInfo, 0, len(cm.containers))
	for _, container := range cm.containers {
		containers = append(containers, container)
	}
	return containers
}

// ListPods returns all discovered pods
func (cm *ContainerManager) ListPods() []*PodInfo {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	pods := make([]*PodInfo, 0, len(cm.pods))
	for _, pod := range cm.pods {
		pods = append(pods, pod)
	}
	return pods
}

// ListServices returns all discovered services
func (cm *ContainerManager) ListServices() []*ServiceInfo {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	services := make([]*ServiceInfo, 0, len(cm.services))
	for _, service := range cm.services {
		services = append(services, service)
	}
	return services
}

// IsRunning returns whether the container manager is running
func (cm *ContainerManager) IsRunning() bool {
	return cm.running
}

// GetStats returns container manager statistics
func (cm *ContainerManager) GetStats() map[string]interface{} {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	return map[string]interface{}{
		"containers_discovered": len(cm.containers),
		"namespaces_discovered": len(cm.namespaces),
		"pods_discovered":       len(cm.pods),
		"services_discovered":   len(cm.services),
		"kubernetes_enabled":    cm.config.EnableKubernetesIntegration,
		"namespace_isolation":   cm.config.EnableNamespaceIsolation,
		"service_mesh_support":  cm.config.EnableServiceMeshSupport,
	}
}

// Simplified implementations for runtime and client
func NewDockerRuntime() ContainerRuntime {
	return &DockerRuntime{}
}

func NewKubernetesClient(config *K8sConfig) *KubernetesClient {
	return &KubernetesClient{config: config}
}

// DockerRuntime simplified Docker runtime implementation
type DockerRuntime struct{}

func (dr *DockerRuntime) ListContainers() ([]*ContainerInfo, error) {
	// Simplified implementation - would use Docker API
	containers := make([]*ContainerInfo, 0)
	
	// Read from /proc to find container processes
	if err := filepath.WalkDir("/proc", func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		
		// Check if this is a PID directory
		if pid, err := strconv.Atoi(d.Name()); err == nil {
			if container := dr.getContainerFromPID(pid); container != nil {
				containers = append(containers, container)
			}
		}
		
		return nil
	}); err != nil {
		return nil, err
	}
	
	return containers, nil
}

func (dr *DockerRuntime) GetContainer(id string) (*ContainerInfo, error) {
	// Simplified implementation
	return nil, fmt.Errorf("not implemented")
}

func (dr *DockerRuntime) GetContainerLogs(id string, lines int) ([]string, error) {
	// Simplified implementation
	return nil, fmt.Errorf("not implemented")
}

func (dr *DockerRuntime) GetContainerStats(id string) (*ResourceUsage, error) {
	// Simplified implementation
	return &ResourceUsage{}, nil
}

func (dr *DockerRuntime) getContainerFromPID(pid int) *ContainerInfo {
	// Check if this PID belongs to a container by examining cgroup
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return nil
	}
	
	// Look for container ID in cgroup path
	if strings.Contains(string(data), "docker") || strings.Contains(string(data), "containerd") {
		return &ContainerInfo{
			ID:        fmt.Sprintf("container-%d", pid),
			PID:       pid,
			Runtime:   "docker",
			State:     "running",
			CreatedAt: time.Now(),
		}
	}
	
	return nil
}

// Simplified Kubernetes client methods
func (kc *KubernetesClient) ListPods(namespace string) ([]*PodInfo, error) {
	// Simplified implementation - would use Kubernetes API
	return []*PodInfo{}, nil
}

func (kc *KubernetesClient) ListServices(namespace string) ([]*ServiceInfo, error) {
	// Simplified implementation - would use Kubernetes API
	return []*ServiceInfo{}, nil
}
