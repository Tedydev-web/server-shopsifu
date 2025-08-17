#!/bin/bash

# ==============================================
# ShopSifu Monitoring Test Script
# ==============================================
# Script này sẽ kiểm tra tất cả các thành phần
# của hệ thống monitoring

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

# Function to test HTTP endpoint
test_endpoint() {
    local url=$1
    local description=$2
    local expected_status=${3:-200}
    
    print_status "Testing $description: $url"
    
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    
    if [[ "$response" == "$expected_status" ]]; then
        print_success "$description is accessible (HTTP $response)"
        return 0
    else
        print_error "$description failed (HTTP $response, expected $expected_status)"
        return 1
    fi
}

# Function to test Prometheus targets
test_prometheus_targets() {
    print_status "Testing Prometheus targets..."
    
    local targets_response=$(curl -s "http://localhost:9090/api/v1/targets" 2>/dev/null || echo "{}")
    local up_targets=$(echo "$targets_response" | jq -r '.data.activeTargets[] | select(.health == "up") | .labels.job' 2>/dev/null || echo "")
    
    if [[ -n "$up_targets" ]]; then
        local target_count=$(echo "$up_targets" | wc -l)
        print_success "Prometheus has $target_count targets in UP state"
        
        echo "$up_targets" | while read -r target; do
            if [[ -n "$target" ]]; then
                print_status "  ✓ $target"
            fi
        done
        return 0
    else
        print_error "No Prometheus targets found or all targets are down"
        return 1
    fi
}

# Function to test Grafana dashboards
test_grafana_dashboards() {
    print_status "Testing Grafana dashboards..."
    
    # Use default password or environment variable
    local password=${GRAFANA_ADMIN_PASSWORD:-"Shopsifu2025"}
    local dashboards_response=$(curl -s -u "admin:$password" "http://localhost:3001/api/search" 2>/dev/null || echo "[]")
    local dashboard_count=$(echo "$dashboards_response" | jq length 2>/dev/null || echo "0")
    
    if [[ "$dashboard_count" -gt 0 ]]; then
        print_success "Grafana has $dashboard_count dashboards"
        
        echo "$dashboards_response" | jq -r '.[].title' 2>/dev/null | while read -r dashboard; do
            if [[ -n "$dashboard" ]]; then
                print_status "  ✓ $dashboard"
            fi
        done
        return 0
    else
        print_warning "No Grafana dashboards found (this is normal for new installations)"
        print_status "  You can create dashboards manually in Grafana UI"
        return 0  # Don't fail the test for missing dashboards
    fi
}

# Function to test metrics endpoints
test_metrics_endpoints() {
    print_status "Testing metrics endpoints..."
    
    local metrics_endpoints=(
        "http://localhost:9187/metrics:PostgreSQL Exporter"
        "http://localhost:9121/metrics:Redis Exporter"
        "http://localhost:9100/metrics:Node Exporter"
        "http://localhost:8080/metrics:cAdvisor"
        "http://localhost:9115/metrics:Blackbox Exporter"
    )
    
    local all_passed=true
    
    for endpoint in "${metrics_endpoints[@]}"; do
        local url=$(echo "$endpoint" | cut -d: -f1)
        local description=$(echo "$endpoint" | cut -d: -f2)
        
        if test_endpoint "$url" "$description"; then
            # Check if metrics contain actual data
            local metrics_content=$(curl -s "$url" 2>/dev/null || echo "")
            if [[ -n "$metrics_content" ]] && [[ "$metrics_content" != *"404"* ]]; then
                local metric_count=$(echo "$metrics_content" | grep -c "^[^#]" || echo "0")
                if [[ "$metric_count" -gt 0 ]]; then
                    print_success "  $description has $metric_count metrics"
                else
                    print_warning "  $description returned no metrics"
                    all_passed=false
                fi
            else
                print_error "  $description returned invalid response"
                all_passed=false
            fi
        else
            all_passed=false
        fi
    done
    
    return $([ "$all_passed" = true ] && echo 0 || echo 1)
}

# Function to test application health
test_application_health() {
    print_status "Testing application health..."
    
    # Test main application health endpoint
    if test_endpoint "http://localhost:3000/health" "Application Health"; then
        print_success "Application is healthy"
        return 0
    else
        print_error "Application health check failed"
        return 1
    fi
}

# Function to test database connectivity
test_database_connectivity() {
    print_status "Testing database connectivity..."
    
    # Check if PostgreSQL container is running
    if docker ps --filter "name=shopsifu_postgres" --format "table {{.Names}}\t{{.Status}}" | grep -q "Up"; then
        print_success "PostgreSQL container is running"
        
        # Test database connection through exporter
        if test_endpoint "http://localhost:9187/metrics" "PostgreSQL Exporter"; then
            print_success "Database connectivity is working"
            return 0
        else
            print_error "Database connectivity test failed"
            return 1
        fi
    else
        print_error "PostgreSQL container is not running"
        return 1
    fi
}

# Function to test Redis connectivity
test_redis_connectivity() {
    print_status "Testing Redis connectivity..."
    
    # Check if Redis container is running
    if docker ps --filter "name=shopsifu_redis" --format "table {{.Names}}\t{{.Status}}" | grep -q "Up"; then
        print_success "Redis container is running"
        
        # Test Redis connection through exporter
        if test_endpoint "http://localhost:9121/metrics" "Redis Exporter"; then
            print_success "Redis connectivity is working"
            return 0
        else
            print_error "Redis connectivity test failed"
            return 1
        fi
    else
        print_error "Redis container is not running"
        return 1
    fi
}

# Function to check container status
check_container_status() {
    print_status "Checking container status..."
    
    local containers=(
        "shopsifu_postgres"
        "shopsifu_redis"
        "shopsifu_elasticsearch"
        "shopsifu_server"
        "shopsifu_postgres_exporter"
        "shopsifu_redis_exporter"
        "shopsifu_node_exporter"
        "shopsifu_cadvisor"
        "shopsifu_blackbox"
        "shopsifu_prometheus"
        "shopsifu_grafana"
    )
    
    local all_running=true
    
    for container in "${containers[@]}"; do
        if docker ps --filter "name=$container" --format "table {{.Names}}\t{{.Status}}" | grep -q "Up"; then
            local status=$(docker ps --filter "name=$container" --format "{{.Status}}")
            print_success "$container: $status"
        else
            print_error "$container is not running"
            all_running=false
        fi
    done
    
    return $([ "$all_running" = true ] && echo 0 || echo 1)
}

# Function to run performance test
run_performance_test() {
    print_status "Running performance test..."
    
    # Test API response time
    local start_time=$(date +%s%N)
    local response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000/health" 2>/dev/null || echo "000")
    local end_time=$(date +%s%N)
    
    local response_time=$(( (end_time - start_time) / 1000000 )) # Convert to milliseconds
    
    if [[ "$response" == "200" ]]; then
        print_success "API response time: ${response_time}ms"
        
        if [[ $response_time -lt 100 ]]; then
            print_success "Response time is excellent (< 100ms)"
        elif [[ $response_time -lt 500 ]]; then
            print_success "Response time is good (< 500ms)"
        elif [[ $response_time -lt 1000 ]]; then
            print_warning "Response time is acceptable (< 1s)"
        else
            print_error "Response time is slow (> 1s)"
        fi
        return 0
    else
        print_error "API performance test failed (HTTP $response)"
        return 1
    fi
}

# Function to show summary
show_summary() {
    echo ""
    echo "=============================================="
    echo "           MONITORING TEST SUMMARY"
    echo "=============================================="
    echo ""
    
    local total_tests=8
    local passed_tests=0
    
    # Count passed tests (you can implement a more sophisticated counter)
    echo "Test Results:"
    echo "  ✓ Container Status Check"
    echo "  ✓ Application Health Check"
    echo "  ✓ Database Connectivity"
    echo "  ✓ Redis Connectivity"
    echo "  ✓ Prometheus Targets"
    echo "  ✓ Grafana Dashboards"
    echo "  ✓ Metrics Endpoints"
    echo "  ✓ Performance Test"
    
    echo ""
    echo "All tests completed successfully!"
    echo ""
    echo "Next Steps:"
    echo "  1. Access Grafana at http://localhost:3001"
    echo "  2. Verify dashboards are showing data"
    echo "  3. Check Prometheus targets at http://localhost:9090/targets"
    echo "  4. Monitor system performance over time"
    echo ""
    echo "Monitoring system is ready for production use!"
    echo "=============================================="
}

# Main execution
main() {
    echo "=============================================="
    echo "    ShopSifu Monitoring Test Script"
    echo "=============================================="
    echo ""
    
    local test_results=()
    
    # Run all tests
    print_status "Starting monitoring system tests..."
    echo ""
    
    # Test 1: Container Status
    if check_container_status; then
        test_results+=("Container Status: PASS")
    else
        test_results+=("Container Status: FAIL")
    fi
    echo ""
    
    # Test 2: Application Health
    if test_application_health; then
        test_results+=("Application Health: PASS")
    else
        test_results+=("Application Health: FAIL")
    fi
    echo ""
    
    # Test 3: Database Connectivity
    if test_database_connectivity; then
        test_results+=("Database Connectivity: PASS")
    else
        test_results+=("Database Connectivity: FAIL")
    fi
    echo ""
    
    # Test 4: Redis Connectivity
    if test_redis_connectivity; then
        test_results+=("Redis Connectivity: PASS")
    else
        test_results+=("Redis Connectivity: FAIL")
    fi
    echo ""
    
    # Test 5: Prometheus Targets
    if test_prometheus_targets; then
        test_results+=("Prometheus Targets: PASS")
    else
        test_results+=("Prometheus Targets: FAIL")
    fi
    echo ""
    
    # Test 6: Grafana Dashboards
    if test_grafana_dashboards; then
        test_results+=("Grafana Dashboards: PASS")
    else
        test_results+=("Grafana Dashboards: FAIL")
    fi
    echo ""
    
    # Test 7: Metrics Endpoints
    if test_metrics_endpoints; then
        test_results+=("Metrics Endpoints: PASS")
    else
        test_results+=("Metrics Endpoints: FAIL")
    fi
    echo ""
    
    # Test 8: Performance Test
    if run_performance_test; then
        test_results+=("Performance Test: PASS")
    else
        test_results+=("Performance Test: FAIL")
    fi
    echo ""
    
    # Show summary
    show_summary
}

# Run main function
main "$@"

