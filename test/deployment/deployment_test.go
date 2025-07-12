package deployment

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDockerfile tests Dockerfile validation
func TestDockerfile(t *testing.T) {
	dockerfilePath := "../../Dockerfile"

	// Check if Dockerfile exists
	_, err := os.Stat(dockerfilePath)
	require.NoError(t, err, "Dockerfile should exist")

	// Read Dockerfile content
	content, err := os.ReadFile(dockerfilePath)
	require.NoError(t, err, "Should be able to read Dockerfile")

	dockerfileContent := string(content)

	// Validate Dockerfile structure
	assert.Contains(t, dockerfileContent, "FROM golang:", "Should use Go base image")
	assert.Contains(t, dockerfileContent, "FROM alpine:", "Should use Alpine for production stage")
	assert.Contains(t, dockerfileContent, "COPY --from=builder", "Should use multi-stage build")
	assert.Contains(t, dockerfileContent, "EXPOSE 8080", "Should expose dashboard port")
	assert.Contains(t, dockerfileContent, "9090", "Should expose metrics port")
	assert.Contains(t, dockerfileContent, "HEALTHCHECK", "Should include health check")
	assert.Contains(t, dockerfileContent, "USER ebpf", "Should run as non-root user")
}

// TestDockerCompose tests Docker Compose configuration
func TestDockerCompose(t *testing.T) {
	composePath := "../../docker-compose.yml"

	// Check if docker-compose.yml exists
	_, err := os.Stat(composePath)
	require.NoError(t, err, "docker-compose.yml should exist")

	// Read docker-compose.yml content
	content, err := os.ReadFile(composePath)
	require.NoError(t, err, "Should be able to read docker-compose.yml")

	composeContent := string(content)

	// Validate docker-compose structure
	assert.Contains(t, composeContent, "version:", "Should specify version")
	assert.Contains(t, composeContent, "services:", "Should define services")
	assert.Contains(t, composeContent, "ebpf-tracer:", "Should include eBPF tracer service")
	assert.Contains(t, composeContent, "jaeger:", "Should include Jaeger service")
	assert.Contains(t, composeContent, "prometheus:", "Should include Prometheus service")
	assert.Contains(t, composeContent, "grafana:", "Should include Grafana service")
	assert.Contains(t, composeContent, "privileged: true", "Should run privileged for eBPF")
	assert.Contains(t, composeContent, "network_mode: host", "Should use host networking")
}

// TestKubernetesManifests tests Kubernetes manifest validation
func TestKubernetesManifests(t *testing.T) {
	manifestFiles := []string{
		"../../deployments/kubernetes/namespace.yaml",
		"../../deployments/kubernetes/daemonset.yaml",
		"../../deployments/kubernetes/monitoring.yaml",
	}

	for _, file := range manifestFiles {
		t.Run(fmt.Sprintf("Validate %s", file), func(t *testing.T) {
			// Check if file exists
			_, err := os.Stat(file)
			require.NoError(t, err, "Manifest file should exist")

			// Read file content
			content, err := os.ReadFile(file)
			require.NoError(t, err, "Should be able to read manifest file")

			// Basic YAML validation
			assert.Contains(t, string(content), "apiVersion", "Should contain apiVersion")
			assert.Contains(t, string(content), "kind", "Should contain kind")
			assert.Contains(t, string(content), "metadata", "Should contain metadata")
		})
	}
}

// TestHelmChart tests Helm chart validation
func TestHelmChart(t *testing.T) {
	chartPath := "../../deployments/helm/ebpf-http-tracer"

	// Check Chart.yaml
	t.Run("Chart.yaml", func(t *testing.T) {
		chartFile := fmt.Sprintf("%s/Chart.yaml", chartPath)
		_, err := os.Stat(chartFile)
		require.NoError(t, err, "Chart.yaml should exist")

		content, err := os.ReadFile(chartFile)
		require.NoError(t, err, "Should be able to read Chart.yaml")

		assert.Contains(t, string(content), "name: ebpf-http-tracer", "Should contain chart name")
		assert.Contains(t, string(content), "version:", "Should contain version")
		assert.Contains(t, string(content), "appVersion:", "Should contain appVersion")
	})

	// Check values.yaml
	t.Run("values.yaml", func(t *testing.T) {
		valuesFile := fmt.Sprintf("%s/values.yaml", chartPath)
		_, err := os.Stat(valuesFile)
		require.NoError(t, err, "values.yaml should exist")

		content, err := os.ReadFile(valuesFile)
		require.NoError(t, err, "Should be able to read values.yaml")

		assert.Contains(t, string(content), "image:", "Should contain image configuration")
		assert.Contains(t, string(content), "service:", "Should contain service configuration")
		assert.Contains(t, string(content), "config:", "Should contain config section")
	})

	// Check templates directory
	t.Run("Templates", func(t *testing.T) {
		templatesDir := fmt.Sprintf("%s/templates", chartPath)
		_, err := os.Stat(templatesDir)
		require.NoError(t, err, "templates directory should exist")

		// Check for essential templates
		essentialTemplates := []string{
			"daemonset.yaml",
			"_helpers.tpl",
		}

		for _, template := range essentialTemplates {
			templateFile := fmt.Sprintf("%s/%s", templatesDir, template)
			_, err := os.Stat(templateFile)
			assert.NoError(t, err, fmt.Sprintf("Template %s should exist", template))
		}
	})
}

// TestDeploymentScript tests the deployment script
func TestDeploymentScript(t *testing.T) {
	scriptPath := "../../scripts/deploy.sh"

	// Check if script exists
	_, err := os.Stat(scriptPath)
	require.NoError(t, err, "Deployment script should exist")

	// Check if script is executable
	info, err := os.Stat(scriptPath)
	require.NoError(t, err)
	
	mode := info.Mode()
	assert.True(t, mode&0111 != 0, "Script should be executable")

	// Read script content for basic validation
	content, err := os.ReadFile(scriptPath)
	require.NoError(t, err, "Should be able to read deployment script")

	scriptContent := string(content)
	assert.Contains(t, scriptContent, "#!/bin/bash", "Should be a bash script")
	assert.Contains(t, scriptContent, "deploy()", "Should contain deploy function")
	assert.Contains(t, scriptContent, "upgrade()", "Should contain upgrade function")
	assert.Contains(t, scriptContent, "uninstall()", "Should contain uninstall function")
	assert.Contains(t, scriptContent, "helm", "Should use helm commands")
	assert.Contains(t, scriptContent, "kubectl", "Should use kubectl commands")
}

// TestMonitoringConfiguration tests monitoring configuration files
func TestMonitoringConfiguration(t *testing.T) {
	configFiles := map[string][]string{
		"../../deployments/monitoring/prometheus.yml": {
			"global:",
			"scrape_configs:",
			"ebpf-http-tracer",
		},
		"../../deployments/monitoring/alert_rules.yml": {
			"groups:",
			"TracerDown",
			"HighHTTPErrorRate",
		},
		"../../deployments/monitoring/alertmanager.yml": {
			"global:",
			"route:",
			"receivers:",
		},
	}

	for file, expectedContent := range configFiles {
		t.Run(fmt.Sprintf("Validate %s", file), func(t *testing.T) {
			// Check if file exists
			_, err := os.Stat(file)
			require.NoError(t, err, "Configuration file should exist")

			// Read and validate content
			content, err := os.ReadFile(file)
			require.NoError(t, err, "Should be able to read configuration file")

			fileContent := string(content)
			for _, expected := range expectedContent {
				assert.Contains(t, fileContent, expected, 
					fmt.Sprintf("File should contain '%s'", expected))
			}
		})
	}
}

// TestResourceRequirements tests resource requirement specifications
func TestResourceRequirements(t *testing.T) {
	// Test DaemonSet resource requirements
	daemonsetFile := "../../deployments/kubernetes/daemonset.yaml"
	content, err := os.ReadFile(daemonsetFile)
	require.NoError(t, err)

	daemonsetContent := string(content)
	assert.Contains(t, daemonsetContent, "resources:", "Should specify resource requirements")
	assert.Contains(t, daemonsetContent, "requests:", "Should specify resource requests")
	assert.Contains(t, daemonsetContent, "limits:", "Should specify resource limits")
	assert.Contains(t, daemonsetContent, "memory:", "Should specify memory requirements")
	assert.Contains(t, daemonsetContent, "cpu:", "Should specify CPU requirements")
}

// TestSecurityConfiguration tests security-related configurations
func TestSecurityConfiguration(t *testing.T) {
	// Test DaemonSet security context
	daemonsetFile := "../../deployments/kubernetes/daemonset.yaml"
	content, err := os.ReadFile(daemonsetFile)
	require.NoError(t, err)

	daemonsetContent := string(content)
	assert.Contains(t, daemonsetContent, "securityContext:", "Should specify security context")
	assert.Contains(t, daemonsetContent, "privileged: true", "Should run privileged for eBPF")
	assert.Contains(t, daemonsetContent, "SYS_ADMIN", "Should have SYS_ADMIN capability")
	assert.Contains(t, daemonsetContent, "NET_ADMIN", "Should have NET_ADMIN capability")

	// Test RBAC configuration
	namespaceFile := "../../deployments/kubernetes/namespace.yaml"
	content, err = os.ReadFile(namespaceFile)
	require.NoError(t, err)

	namespaceContent := string(content)
	assert.Contains(t, namespaceContent, "ServiceAccount", "Should create service account")
	assert.Contains(t, namespaceContent, "ClusterRole", "Should create cluster role")
	assert.Contains(t, namespaceContent, "ClusterRoleBinding", "Should create cluster role binding")
}

// BenchmarkDeploymentSize benchmarks deployment artifact sizes
func BenchmarkDeploymentSize(b *testing.B) {
	files := []string{
		"../../deployments/kubernetes/daemonset.yaml",
		"../../deployments/kubernetes/monitoring.yaml",
		"../../deployments/helm/ebpf-http-tracer/values.yaml",
	}

	for _, file := range files {
		b.Run(fmt.Sprintf("Size_%s", file), func(b *testing.B) {
			info, err := os.Stat(file)
			if err != nil {
				b.Skip("File not found")
			}
			
			b.ReportMetric(float64(info.Size()), "bytes")
		})
	}
}
