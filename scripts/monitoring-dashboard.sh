#!/bin/bash

# 📊 ShopSifu Monitoring Dashboard Script
# Hiển thị trạng thái real-time của hệ thống monitoring

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${PURPLE}$1${NC}"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_metric() {
    echo -e "${CYAN}$1${NC}"
}

# Function to check service health
check_service_health() {
    local service=$1
    local port=$2
    local endpoint=$3
    
    if curl -s "http://localhost:$port$endpoint" > /dev/null 2>&1; then
        print_success "$service (:$port) - Healthy"
        return 0
    else
        print_error "$service (:$port) - Unhealthy"
        return 1
    fi
}

# Function to get container status
get_container_status() {
    local service=$1
    local status=$(docker compose ps -q $service 2>/dev/null | xargs docker inspect --format='{{.State.Status}}' 2>/dev/null || echo "not_found")
    local health=$(docker compose ps -q $service 2>/dev/null | xargs docker inspect --format='{{.State.Health.Status}}' 2>/dev/null || echo "none")
    
    if [[ "$status" == "running" ]]; then
        if [[ "$health" == "healthy" ]]; then
            print_success "$service - Running (Healthy)"
        elif [[ "$health" == "starting" ]]; then
            print_warning "$service - Running (Starting)"
        else
            print_warning "$service - Running (Health: $health)"
        fi
    elif [[ "$status" == "not_found" ]]; then
        print_error "$service - Not Found"
    else
        print_error "$service - $status"
    fi
}

# Function to get Prometheus targets status
get_prometheus_targets() {
    local targets=$(curl -s "http://localhost:9090/api/v1/targets" 2>/dev/null | jq -r '.data.activeTargets[] | "\(.labels.job):\(.health)"' 2>/dev/null || echo "")
    
    if [[ -n "$targets" ]]; then
        echo "$targets" | while read -r target; do
            if [[ -n "$target" ]]; then
                local job=$(echo "$target" | cut -d: -f1)
                local health=$(echo "$target" | cut -d: -f2)
                
                if [[ "$health" == "up" ]]; then
                    print_success "  $job"
                else
                    print_error "  $job"
                fi
            fi
        done
    else
        print_warning "  No targets available"
    fi
}

# Function to get system metrics
get_system_metrics() {
    # CPU Usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')
    print_metric "CPU Usage: ${cpu_usage}%"
    
    # Memory Usage
    local mem_info=$(free -m | awk 'NR==2{printf "%.1f%%", $3*100/$2}')
    print_metric "Memory Usage: ${mem_info}"
    
    # Disk Usage
    local disk_usage=$(df -h / | awk 'NR==2{print $5}')
    print_metric "Disk Usage: ${disk_usage}"
    
    # Docker containers
    local container_count=$(docker ps --format "table {{.Names}}" | wc -l)
    local running_count=$(docker ps --format "table {{.Names}}" | grep -v "NAMES" | wc -l)
    print_metric "Docker Containers: ${running_count}/${container_count} running"
}

# Function to get Redis metrics
get_redis_metrics() {
    local metrics=$(curl -s "http://localhost:9121/metrics" 2>/dev/null)
    
    if [[ -n "$metrics" ]]; then
        local connected_clients=$(echo "$metrics" | grep "redis_connected_clients " | awk '{print $2}')
        local memory_used=$(echo "$metrics" | grep "redis_memory_used_bytes " | awk '{print $2}')
        local memory_max=$(echo "$metrics" | grep "redis_memory_max_bytes " | awk '{print $2}')
        
        if [[ -n "$connected_clients" ]]; then
            print_metric "Redis Clients: ${connected_clients}"
        fi
        
        if [[ -n "$memory_used" && -n "$memory_max" ]]; then
            local memory_percent=$(awk "BEGIN {printf \"%.1f\", ($memory_used/$memory_max)*100}")
            print_metric "Redis Memory: ${memory_percent}%"
        fi
    else
        print_warning "Redis metrics not available"
    fi
}

# Function to get PostgreSQL metrics
get_postgres_metrics() {
    local metrics=$(curl -s "http://localhost:9187/metrics" 2>/dev/null)
    
    if [[ -n "$metrics" ]]; then
        local active_connections=$(echo "$metrics" | grep "pg_stat_database_numbackends " | awk '{print $2}')
        local database_size=$(echo "$metrics" | grep "pg_database_size_bytes " | awk '{print $2}')
        
        if [[ -n "$active_connections" ]]; then
            print_metric "PostgreSQL Connections: ${active_connections}"
        fi
        
        if [[ -n "$database_size" ]]; then
            local size_mb=$(awk "BEGIN {printf \"%.1f\", $database_size/1024/1024}")
            print_metric "Database Size: ${size_mb} MB"
        fi
    else
        print_warning "PostgreSQL metrics not available"
    fi
}

# Main dashboard
main() {
    clear
    
    print_header "=============================================="
    print_header "    🚀 ShopSifu Monitoring Dashboard"
    print_header "=============================================="
    echo ""
    
    # System Overview
    print_header "🖥️  SYSTEM OVERVIEW"
    get_system_metrics
    echo ""
    
    # Container Status
    print_header "🐳 CONTAINER STATUS"
    get_container_status "shopsifu_prometheus"
    get_container_status "shopsifu_grafana"
    get_container_status "shopsifu_alertmanager"
    get_container_status "shopsifu_blackbox"
    get_container_status "shopsifu_postgres_exporter"
    get_container_status "shopsifu_redis_exporter"
    get_container_status "shopsifu_node_exporter"
    get_container_status "shopsifu_cadvisor"
    echo ""
    
    # Service Health
    print_header "🏥 SERVICE HEALTH"
    check_service_health "Prometheus" "9090" "/api/v1/targets"
    check_service_health "Grafana" "3001" "/api/health"
    check_service_health "Alertmanager" "9093" "/api/v1/status"
    check_service_health "Redis Exporter" "9121" "/metrics"
    check_service_health "PostgreSQL Exporter" "9187" "/metrics"
    echo ""
    
    # Prometheus Targets
    print_header "🎯 PROMETHEUS TARGETS"
    get_prometheus_targets
    echo ""
    
    # Application Metrics
    print_header "📊 APPLICATION METRICS"
    get_redis_metrics
    get_postgres_metrics
    echo ""
    
    # Access Information
    print_header "🌐 ACCESS URLs"
    print_metric "Prometheus:     http://localhost:9090"
    print_metric "Grafana:        http://localhost:3001"
    print_metric "Alertmanager:   http://localhost:9093"
    print_metric "Redis Exporter: http://localhost:9121/metrics"
    print_metric "Postgres Exp:   http://localhost:9187/metrics"
    echo ""
    
    # Quick Actions
    print_header "⚡ QUICK ACTIONS"
    print_metric "Test Monitoring: ./scripts/test-monitoring.sh"
    print_metric "View Logs:      docker compose logs -f [service]"
    print_metric "Restart All:    docker compose restart"
    print_metric "Stop All:       docker compose down"
    echo ""
    
    print_header "=============================================="
    print_header "Last Updated: $(date '+%Y-%m-%d %H:%M:%S')"
    print_header "=============================================="
}

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    print_error "jq is not installed. Please install it first: sudo apt-get install jq"
    exit 1
fi

# Run main function
main "$@"
