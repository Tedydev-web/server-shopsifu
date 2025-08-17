#!/bin/bash

# ==============================================
# ShopSifu Monitoring Setup Script
# ==============================================
# Script này sẽ thiết lập hoàn chỉnh hệ thống monitoring
# bao gồm Prometheus, Grafana và các exporters

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Function to create monitoring directories
create_directories() {
    print_status "Creating monitoring directories..."
    
    mkdir -p monitoring/prometheus/rules
    mkdir -p monitoring/grafana/provisioning/datasources
    mkdir -p monitoring/grafana/provisioning/dashboards
    mkdir -p monitoring/grafana/dashboards
    mkdir -p monitoring/postgres-exporter
    mkdir -p monitoring/blackbox
    
    print_success "Monitoring directories created"
}

# Function to set proper permissions
set_permissions() {
    print_status "Setting proper permissions..."
    
    # Set read permissions for monitoring files
    chmod -R 644 monitoring/
    chmod -R +X monitoring/
    
    # Set execute permissions for scripts
    chmod +x scripts/*.sh
    
    print_success "Permissions set correctly"
}

# Function to validate configuration files
validate_configs() {
    print_status "Validating configuration files..."
    
    # Check if required files exist
    local required_files=(
        "monitoring/prometheus/server.yml"
        "monitoring/prometheus/rules/alerts.yml"
        "monitoring/grafana/provisioning/datasources/prometheus.yml"
        "monitoring/grafana/provisioning/dashboards/dashboards.yml"
        "monitoring/grafana/dashboards/system-overview.json"
        "monitoring/grafana/dashboards/database-performance.json"
        "monitoring/grafana/dashboards/container-performance.json"
        "monitoring/postgres-exporter/queries.yml"
        "monitoring/blackbox/config.yml"
        "docker-compose.yml"
        ".env.docker"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            print_error "Required file not found: $file"
            exit 1
        fi
    done
    
    print_success "All configuration files are present"
}

# Function to check environment variables
check_env_vars() {
    print_status "Checking environment variables..."
    
    # Check if .env.docker exists and has required variables
    if [[ ! -f ".env.docker" ]]; then
        print_error ".env.docker file not found"
        exit 1
    fi
    
    # Source environment variables
    set -a
    source .env.docker
    set +a
    
    # Check required variables
    local required_vars=(
        "GRAFANA_ADMIN_PASSWORD"
        "POSTGRES_USER"
        "POSTGRES_PASSWORD"
        "POSTGRES_DB"
        "REDIS_PASSWORD"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            print_error "Required environment variable not set: $var"
            exit 1
        fi
    done
    
    print_success "Environment variables are properly configured"
}

# Function to stop existing services
stop_existing_services() {
    print_status "Stopping existing services..."
    
    if docker compose ps | grep -q "Up"; then
        docker compose down
        print_success "Existing services stopped"
    else
        print_status "No existing services running"
    fi
}

# Function to start monitoring services
start_monitoring_services() {
    print_status "Starting monitoring services..."
    
    # Start only monitoring services first
    docker compose up -d postgres-exporter redis-exporter node-exporter cadvisor blackbox prometheus grafana
    
    print_success "Monitoring services started"
}

# Function to wait for services to be ready
wait_for_services() {
    print_status "Waiting for services to be ready..."
    
    local services=(
        "postgres-exporter:9187"
        "redis-exporter:9121"
        "node-exporter:9100"
        "cadvisor:8080"
        "blackbox:9115"
        "prometheus:9090"
        "grafana:3000"
    )
    
    for service in "${services[@]}"; do
        local host_port=(${service//:/ })
        local host=${host_port[0]}
        local port=${host_port[1]}
        
        print_status "Waiting for $host:$port..."
        
        local max_attempts=30
        local attempt=1
        
        while [[ $attempt -le $max_attempts ]]; do
            if curl -s "http://localhost:$port" >/dev/null 2>&1 || \
               curl -s "http://localhost:$port/metrics" >/dev/null 2>&1 || \
               curl -s "http://localhost:$port/api/health" >/dev/null 2>&1; then
                print_success "$host:$port is ready"
                break
            fi
            
            if [[ $attempt -eq $max_attempts ]]; then
                print_error "$host:$port failed to start after $max_attempts attempts"
                exit 1
            fi
            
            print_status "Attempt $attempt/$max_attempts - waiting 10 seconds..."
            sleep 10
            ((attempt++))
        done
    done
}

# Function to verify Prometheus targets
verify_prometheus_targets() {
    print_status "Verifying Prometheus targets..."
    
    local max_attempts=20
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        local targets=$(curl -s "http://localhost:9090/api/v1/targets" 2>/dev/null | jq -r '.data.activeTargets[] | select(.health == "up") | .labels.job' 2>/dev/null || echo "")
        
        if [[ -n "$targets" ]]; then
            local target_count=$(echo "$targets" | wc -l)
            print_success "Prometheus has $target_count targets in UP state"
            echo "$targets" | while read -r target; do
                if [[ -n "$target" ]]; then
                    print_status "  ✓ $target"
                fi
            done
            break
        fi
        
        if [[ $attempt -eq $max_attempts ]]; then
            print_error "Prometheus targets verification failed after $max_attempts attempts"
            exit 1
        fi
        
        print_status "Attempt $attempt/$max_attempts - waiting 15 seconds..."
        sleep 15
        ((attempt++))
    done
}

# Function to verify Grafana dashboards
verify_grafana_dashboards() {
    print_status "Verifying Grafana dashboards..."
    
    local max_attempts=20
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        local dashboards=$(curl -s "http://admin:${GRAFANA_ADMIN_PASSWORD}@localhost:3001/api/search" 2>/dev/null | jq -r '.[].title' 2>/dev/null || echo "")
        
        if [[ -n "$dashboards" ]]; then
            local dashboard_count=$(echo "$dashboards" | wc -l)
            print_success "Grafana has $dashboard_count dashboards"
            echo "$dashboards" | while read -r dashboard; do
                if [[ -n "$dashboard" ]]; then
                    print_status "  ✓ $dashboard"
                fi
            done
            break
        fi
        
        if [[ $attempt -eq $max_attempts ]]; then
            print_error "Grafana dashboards verification failed after $max_attempts attempts"
            exit 1
        fi
        
        print_status "Attempt $attempt/$max_attempts - waiting 15 seconds..."
        sleep 15
        ((attempt++))
    done
}

# Function to start all services
start_all_services() {
    print_status "Starting all services..."
    
    docker compose up -d
    
    print_success "All services started"
}

# Function to show final status
show_final_status() {
    print_status "Showing final service status..."
    
    echo ""
    echo "=============================================="
    echo "           MONITORING SETUP COMPLETE"
    echo "=============================================="
    echo ""
    echo "Services Status:"
    docker compose ps
    echo ""
    echo "Access URLs:"
    echo "  Grafana:      http://localhost:3001 (admin/${GRAFANA_ADMIN_PASSWORD})"
    echo "  Prometheus:   http://localhost:9090"
    echo "  cAdvisor:     http://localhost:8080"
    echo "  Node Exporter: http://localhost:9100"
    echo ""
    echo "Dashboards Available:"
    echo "  - System Overview"
    echo "  - Database Performance"
    echo "  - Container Performance"
    echo ""
    echo "Next Steps:"
    echo "  1. Access Grafana at http://localhost:3001"
    echo "  2. Login with admin/${GRAFANA_ADMIN_PASSWORD}"
    echo "  3. Verify Prometheus datasource is working"
    echo "  4. Check that dashboards are loaded"
    echo "  5. Configure alerts if needed"
    echo ""
    echo "Monitoring is now active and collecting metrics!"
    echo "=============================================="
}

# Main execution
main() {
    echo "=============================================="
    echo "    ShopSifu Monitoring Setup Script"
    echo "=============================================="
    echo ""
    
    # Check prerequisites
    check_docker
    
    # Create directories and set permissions
    create_directories
    set_permissions
    
    # Validate configuration
    validate_configs
    check_env_vars
    
    # Stop existing services
    stop_existing_services
    
    # Start monitoring services
    start_monitoring_services
    
    # Wait for services to be ready
    wait_for_services
    
    # Verify Prometheus targets
    verify_prometheus_targets
    
    # Verify Grafana dashboards
    verify_grafana_dashboards
    
    # Start all services
    start_all_services
    
    # Show final status
    show_final_status
}

# Run main function
main "$@"

