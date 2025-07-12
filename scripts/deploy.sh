#!/bin/bash

# eBPF HTTP Tracer Deployment Script
# This script automates the deployment of the eBPF HTTP tracer with monitoring stack

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NAMESPACE="ebpf-tracing"
RELEASE_NAME="ebpf-tracer"
CHART_PATH="$PROJECT_ROOT/deployments/helm/ebpf-http-tracer"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
eBPF HTTP Tracer Deployment Script

Usage: $0 [OPTIONS] COMMAND

Commands:
    deploy          Deploy the eBPF HTTP tracer and monitoring stack
    upgrade         Upgrade existing deployment
    uninstall       Remove the deployment
    status          Show deployment status
    logs            Show tracer logs
    port-forward    Set up port forwarding for services

Options:
    -n, --namespace NAMESPACE    Kubernetes namespace (default: ebpf-tracing)
    -r, --release RELEASE        Helm release name (default: ebpf-tracer)
    -f, --values-file FILE       Custom values file
    --dry-run                    Show what would be deployed without applying
    --skip-monitoring            Skip monitoring stack deployment
    --skip-build                 Skip Docker image build
    -h, --help                   Show this help message

Examples:
    $0 deploy                    Deploy with default settings
    $0 deploy -f custom.yaml     Deploy with custom values
    $0 upgrade                   Upgrade existing deployment
    $0 uninstall                 Remove deployment
    $0 status                    Show status
    $0 logs                      Show logs
    $0 port-forward              Set up port forwarding

EOF
}

# Parse command line arguments
COMMAND=""
VALUES_FILE=""
DRY_RUN=false
SKIP_MONITORING=false
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -r|--release)
            RELEASE_NAME="$2"
            shift 2
            ;;
        -f|--values-file)
            VALUES_FILE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-monitoring)
            SKIP_MONITORING=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        deploy|upgrade|uninstall|status|logs|port-forward)
            COMMAND="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

if [[ -z "$COMMAND" ]]; then
    log_error "No command specified"
    show_help
    exit 1
fi

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if helm is available
    if ! command -v helm &> /dev/null; then
        log_error "helm is not installed or not in PATH"
        exit 1
    fi
    
    # Check if docker is available (for build)
    if [[ "$SKIP_BUILD" == false ]] && ! command -v docker &> /dev/null; then
        log_error "docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check kubectl connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Build Docker image
build_image() {
    if [[ "$SKIP_BUILD" == true ]]; then
        log_info "Skipping Docker image build"
        return
    fi
    
    log_info "Building Docker image..."
    cd "$PROJECT_ROOT"
    
    if docker build -t ebpf-http-tracer:latest .; then
        log_success "Docker image built successfully"
    else
        log_error "Failed to build Docker image"
        exit 1
    fi
}

# Create namespace
create_namespace() {
    log_info "Creating namespace: $NAMESPACE"
    
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_info "Namespace $NAMESPACE already exists"
    else
        kubectl create namespace "$NAMESPACE"
        log_success "Namespace $NAMESPACE created"
    fi
}

# Deploy function
deploy() {
    log_info "Deploying eBPF HTTP Tracer..."
    
    check_prerequisites
    build_image
    create_namespace
    
    # Prepare helm command
    local helm_cmd="helm install $RELEASE_NAME $CHART_PATH --namespace $NAMESPACE"
    
    if [[ -n "$VALUES_FILE" ]]; then
        helm_cmd="$helm_cmd --values $VALUES_FILE"
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        helm_cmd="$helm_cmd --dry-run"
    fi
    
    if [[ "$SKIP_MONITORING" == true ]]; then
        helm_cmd="$helm_cmd --set jaeger.enabled=false --set prometheus.enabled=false --set grafana.enabled=false"
    fi
    
    # Execute helm install
    if eval "$helm_cmd"; then
        log_success "Deployment completed successfully"
        
        if [[ "$DRY_RUN" == false ]]; then
            log_info "Waiting for pods to be ready..."
            kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=ebpf-http-tracer -n "$NAMESPACE" --timeout=300s
            
            log_success "All pods are ready"
            show_access_info
        fi
    else
        log_error "Deployment failed"
        exit 1
    fi
}

# Upgrade function
upgrade() {
    log_info "Upgrading eBPF HTTP Tracer..."
    
    check_prerequisites
    build_image
    
    # Prepare helm command
    local helm_cmd="helm upgrade $RELEASE_NAME $CHART_PATH --namespace $NAMESPACE"
    
    if [[ -n "$VALUES_FILE" ]]; then
        helm_cmd="$helm_cmd --values $VALUES_FILE"
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        helm_cmd="$helm_cmd --dry-run"
    fi
    
    # Execute helm upgrade
    if eval "$helm_cmd"; then
        log_success "Upgrade completed successfully"
        
        if [[ "$DRY_RUN" == false ]]; then
            log_info "Waiting for pods to be ready..."
            kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=ebpf-http-tracer -n "$NAMESPACE" --timeout=300s
            log_success "All pods are ready"
        fi
    else
        log_error "Upgrade failed"
        exit 1
    fi
}

# Uninstall function
uninstall() {
    log_info "Uninstalling eBPF HTTP Tracer..."
    
    if helm uninstall "$RELEASE_NAME" --namespace "$NAMESPACE"; then
        log_success "Uninstall completed successfully"
        
        log_info "Cleaning up namespace..."
        kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
        log_success "Namespace cleaned up"
    else
        log_error "Uninstall failed"
        exit 1
    fi
}

# Status function
status() {
    log_info "Checking deployment status..."
    
    echo
    log_info "Helm release status:"
    helm status "$RELEASE_NAME" --namespace "$NAMESPACE"
    
    echo
    log_info "Pod status:"
    kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=ebpf-http-tracer
    
    echo
    log_info "Service status:"
    kubectl get services -n "$NAMESPACE"
    
    echo
    log_info "DaemonSet status:"
    kubectl get daemonset -n "$NAMESPACE"
}

# Logs function
logs() {
    log_info "Showing tracer logs..."
    kubectl logs -n "$NAMESPACE" -l app.kubernetes.io/name=ebpf-http-tracer --tail=100 -f
}

# Port forward function
port_forward() {
    log_info "Setting up port forwarding..."
    
    # Get service names
    local dashboard_service=$(kubectl get service -n "$NAMESPACE" -l app.kubernetes.io/name=ebpf-http-tracer -o jsonpath='{.items[0].metadata.name}')
    
    if [[ -n "$dashboard_service" ]]; then
        log_info "Port forwarding dashboard: http://localhost:8080"
        kubectl port-forward -n "$NAMESPACE" "service/$dashboard_service" 8080:8080 &
        
        log_info "Port forwarding metrics: http://localhost:9090"
        kubectl port-forward -n "$NAMESPACE" "service/$dashboard_service" 9090:9090 &
        
        # Check if Jaeger is deployed
        if kubectl get service -n "$NAMESPACE" jaeger-ui &> /dev/null; then
            log_info "Port forwarding Jaeger UI: http://localhost:16686"
            kubectl port-forward -n "$NAMESPACE" service/jaeger-ui 16686:16686 &
        fi
        
        # Check if Prometheus is deployed
        if kubectl get service -n "$NAMESPACE" prometheus &> /dev/null; then
            log_info "Port forwarding Prometheus: http://localhost:9091"
            kubectl port-forward -n "$NAMESPACE" service/prometheus 9091:9090 &
        fi
        
        log_success "Port forwarding setup complete"
        log_info "Press Ctrl+C to stop port forwarding"
        wait
    else
        log_error "No services found for port forwarding"
        exit 1
    fi
}

# Show access information
show_access_info() {
    echo
    log_success "Deployment completed! Access information:"
    echo
    echo "Dashboard:     kubectl port-forward -n $NAMESPACE service/$RELEASE_NAME 8080:8080"
    echo "               Then visit: http://localhost:8080"
    echo
    echo "Metrics:       kubectl port-forward -n $NAMESPACE service/$RELEASE_NAME 9090:9090"
    echo "               Then visit: http://localhost:9090/metrics"
    echo
    echo "Jaeger UI:     kubectl port-forward -n $NAMESPACE service/jaeger-ui 16686:16686"
    echo "               Then visit: http://localhost:16686"
    echo
    echo "Logs:          kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=ebpf-http-tracer -f"
    echo
    echo "Status:        $0 status"
    echo "Port Forward:  $0 port-forward"
    echo
}

# Main execution
case "$COMMAND" in
    deploy)
        deploy
        ;;
    upgrade)
        upgrade
        ;;
    uninstall)
        uninstall
        ;;
    status)
        status
        ;;
    logs)
        logs
        ;;
    port-forward)
        port_forward
        ;;
    *)
        log_error "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac
