#!/bin/bash

# ========================================
# COMPREHENSIVE HEALTH CHECK SCRIPT
# ========================================
# This script performs a complete health check of the entire system
# and generates a detailed report for Discord notification

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
VPS_PATH="${VPS_PATH:-shopsifu/server-shopsifu}"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
HEALTH_CHECK_TIMEOUT=30
MAX_RETRIES=3

# Initialize report data
REPORT_DATA=""
OVERALL_STATUS="healthy"
ERROR_COUNT=0
WARNING_COUNT=0

# Function to add section to report
add_section() {
    local title="$1"
    local content="$2"
    local status="$3"

    case $status in
        "healthy") icon="✅"; color=$GREEN ;;
        "warning") icon="⚠️"; color=$YELLOW ;;
        "error") icon="❌"; color=$RED ;;
        *) icon="ℹ️"; color=$BLUE ;;
    esac

    REPORT_DATA+="\n**${icon} ${title}**\n"
    REPORT_DATA+="```\n${content}\n```\n"
}

# Function to check service health
check_service_health() {
    echo -e "${BLUE}🔍 Checking service health...${NC}"

    local service_status=""
    local healthy_services=0
    local total_services=0

    # Get all services status
    if docker compose -f "${VPS_PATH}/docker-compose.yml" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" > /tmp/service_status 2>/dev/null; then
        service_status=$(cat /tmp/service_status)

        # Count healthy services
        healthy_services=$(docker compose -f "${VPS_PATH}/docker-compose.yml" ps --filter "status=running" --format "{{.Name}}" | wc -l)
        total_services=$(docker compose -f "${VPS_PATH}/docker-compose.yml" ps --format "{{.Name}}" | wc -l)

        if [ "$healthy_services" -eq "$total_services" ] && [ "$total_services" -gt 0 ]; then
            add_section "Service Health" "$service_status\n\n📊 Status: $healthy_services/$total_services services healthy" "healthy"
        elif [ "$healthy_services" -gt 0 ]; then
            add_section "Service Health" "$service_status\n\n⚠️ Status: $healthy_services/$total_services services healthy" "warning"
            WARNING_COUNT=$((WARNING_COUNT + 1))
        else
            add_section "Service Health" "$service_status\n\n❌ Status: $healthy_services/$total_services services healthy" "error"
            ERROR_COUNT=$((ERROR_COUNT + 1))
            OVERALL_STATUS="unhealthy"
        fi
    else
        add_section "Service Health" "❌ Failed to get service status" "error"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        OVERALL_STATUS="unhealthy"
    fi
}

# Function to check application health
check_application_health() {
    echo -e "${BLUE}🔍 Checking application health...${NC}"

    local app_status=""
    local endpoints=("3000" "3003" "3004")
    local healthy_endpoints=0

    for port in "${endpoints[@]}"; do
        if timeout 10 curl -fsS "http://localhost:${port}/health" > /dev/null 2>&1; then
            app_status+="✅ Port ${port}: Healthy\n"
            healthy_endpoints=$((healthy_endpoints + 1))
        else
            app_status+="❌ Port ${port}: Unhealthy\n"
        fi
    done

    # Check detailed health endpoint
    if timeout 10 curl -fsS "http://localhost:3000/health/check" > /tmp/detailed_health 2>/dev/null; then
        local detailed_health=$(cat /tmp/detailed_health | jq -r '.status' 2>/dev/null || echo "unknown")
        app_status+="\n🔍 Detailed Health: ${detailed_health}\n"
    else
        app_status+="\n❌ Detailed Health: Failed\n"
    fi

    if [ "$healthy_endpoints" -eq "${#endpoints[@]}" ]; then
        add_section "Application Health" "$app_status" "healthy"
    elif [ "$healthy_endpoints" -gt 0 ]; then
        add_section "Application Health" "$app_status" "warning"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    else
        add_section "Application Health" "$app_status" "error"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        OVERALL_STATUS="unhealthy"
    fi
}

# Function to check database health
check_database_health() {
    echo -e "${BLUE}🔍 Checking database health...${NC}"

    local db_status=""

    # Check PostgreSQL
    if timeout 10 pg_isready -h localhost -p 5432 -U shopsifu > /dev/null 2>&1; then
        db_status+="✅ PostgreSQL: Healthy\n"
    else
        db_status+="❌ PostgreSQL: Unhealthy\n"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        OVERALL_STATUS="unhealthy"
    fi

    # Check PgBouncer
    if timeout 10 pg_isready -h localhost -p 6432 -U shopsifu > /dev/null 2>&1; then
        db_status+="✅ PgBouncer: Healthy\n"
    else
        db_status+="❌ PgBouncer: Unhealthy\n"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        OVERALL_STATUS="unhealthy"
    fi

    # Check Redis
    if timeout 10 redis-cli -h localhost -p 6379 -a "Shopsifu2025" ping > /dev/null 2>&1; then
        db_status+="✅ Redis: Healthy\n"
    else
        db_status+="❌ Redis: Unhealthy\n"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        OVERALL_STATUS="unhealthy"
    fi

    # Check Elasticsearch
    if timeout 10 curl -fsS "http://localhost:9200/_cluster/health" > /tmp/es_health 2>/dev/null; then
        local es_status=$(cat /tmp/es_health | jq -r '.status' 2>/dev/null || echo "unknown")
        db_status+="✅ Elasticsearch: ${es_status}\n"

        if [ "$es_status" != "green" ]; then
            WARNING_COUNT=$((WARNING_COUNT + 1))
        fi
    else
        db_status+="❌ Elasticsearch: Unhealthy\n"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        OVERALL_STATUS="unhealthy"
    fi

    add_section "Database Health" "$db_status" "healthy"
}

# Function to check monitoring services
check_monitoring_health() {
    echo -e "${BLUE}🔍 Checking monitoring services...${NC}"

    local monitoring_status=""

    # Check Prometheus
    if timeout 10 curl -fsS "http://localhost:9090/-/healthy" > /dev/null 2>&1; then
        monitoring_status+="✅ Prometheus: Healthy\n"
    else
        monitoring_status+="❌ Prometheus: Unhealthy\n"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        OVERALL_STATUS="unhealthy"
    fi

    # Check Grafana
    if timeout 10 curl -fsS "http://localhost:3001/api/health" > /dev/null 2>&1; then
        monitoring_status+="✅ Grafana: Healthy\n"
    else
        monitoring_status+="❌ Grafana: Unhealthy\n"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        OVERALL_STATUS="unhealthy"
    fi

    # Check Kibana
    if timeout 10 curl -fsS "http://localhost:5601/api/status" > /dev/null 2>&1; then
        monitoring_status+="✅ Kibana: Healthy\n"
    else
        monitoring_status+="❌ Kibana: Unhealthy\n"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        OVERALL_STATUS="unhealthy"
    fi

    add_section "Monitoring Health" "$monitoring_status" "healthy"
}

# Function to check system resources
check_system_resources() {
    echo -e "${BLUE}🔍 Checking system resources...${NC}"

    local resource_status=""

    # CPU Usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    resource_status+="🖥️ CPU Usage: ${cpu_usage}%\n"

    # Memory Usage
    local mem_info=$(free -h | grep Mem)
    local mem_total=$(echo $mem_info | awk '{print $2}')
    local mem_used=$(echo $mem_info | awk '{print $3}')
    local mem_free=$(echo $mem_info | awk '{print $4}')
    resource_status+="💾 Memory: ${mem_used}/${mem_total} (${mem_free} free)\n"

    # Disk Usage
    local disk_usage=$(df -h / | tail -1 | awk '{print $5}')
    local disk_available=$(df -h / | tail -1 | awk '{print $4}')
    resource_status+="💿 Disk: ${disk_usage} used (${disk_available} available)\n"

    # Docker Resources
    local docker_containers=$(docker ps --format "{{.Names}}" | wc -l)
    local docker_images=$(docker images --format "{{.Repository}}" | wc -l)
    resource_status+="🐳 Docker: ${docker_containers} containers, ${docker_images} images\n"

    # Network Connections
    local tcp_connections=$(netstat -an | grep ESTABLISHED | wc -l)
    resource_status+="🌐 TCP Connections: ${tcp_connections} established\n"

    add_section "System Resources" "$resource_status" "healthy"
}

# Function to check network connectivity
check_network_health() {
    echo -e "${BLUE}🔍 Checking network connectivity...${NC}"

    local network_status=""
    local endpoints=(
        "api.shopsifu.live:443"
        "grafana.shopsifu.live:443"
        "prometheus.shopsifu.live:443"
    )

    for endpoint in "${endpoints[@]}"; do
        local host=$(echo $endpoint | cut -d: -f1)
        local port=$(echo $endpoint | cut -d: -f2)

        if timeout 10 nc -z "$host" "$port" 2>/dev/null; then
            network_status+="✅ ${host}:${port} - Accessible\n"
        else
            network_status+="❌ ${host}:${port} - Not accessible\n"
            WARNING_COUNT=$((WARNING_COUNT + 1))
        fi
    done

    add_section "Network Connectivity" "$network_status" "healthy"
}

# Function to check recent logs
check_recent_logs() {
    echo -e "${BLUE}🔍 Checking recent logs...${NC}"

    local log_status=""

    # Check for errors in recent logs
    local error_count=$(docker compose -f "${VPS_PATH}/docker-compose.yml" logs --tail=100 2>/dev/null | grep -i "error\|exception\|failed" | wc -l)
    local warning_count=$(docker compose -f "${VPS_PATH}/docker-compose.yml" logs --tail=100 2>/dev/null | grep -i "warn\|warning" | wc -l)

    log_status+="📊 Recent Log Analysis (last 100 lines):\n"
    log_status+="❌ Errors: ${error_count}\n"
    log_status+="⚠️ Warnings: ${warning_count}\n"

    if [ "$error_count" -gt 10 ]; then
        log_status+="\n🚨 High error count detected!\n"
        WARNING_COUNT=$((WARNING_COUNT + 1))
    fi

    add_section "Recent Logs" "$log_status" "healthy"
}

# Function to generate Discord notification
send_discord_notification() {
    if [ -z "$DISCORD_WEBHOOK" ]; then
        echo -e "${YELLOW}⚠️ DISCORD_WEBHOOK not set, skipping notification${NC}"
        return
    fi

    echo -e "${BLUE}📢 Sending Discord notification...${NC}"

    # Determine color based on overall status
    local color
    case $OVERALL_STATUS in
        "healthy") color=3066993 ;; # Green
        "warning") color=16776960 ;; # Yellow
        "unhealthy") color=15158332 ;; # Red
        *) color=7506394 ;; # Blue
    esac

    # Create Discord embed
    local embed_json="{
        \"embeds\": [{
            \"title\": \"🏥 SYSTEM HEALTH REPORT\",
            \"description\": \"Comprehensive health check of Shopsifu production system\",
            \"color\": ${color},
            \"fields\": [
                {
                    \"name\": \"📊 Overall Status\",
                    \"value\": \"${OVERALL_STATUS^^}\",
                    \"inline\": true
                },
                {
                    \"name\": \"❌ Errors\",
                    \"value\": \"${ERROR_COUNT}\",
                    \"inline\": true
                },
                {
                    \"name\": \"⚠️ Warnings\",
                    \"value\": \"${WARNING_COUNT}\",
                    \"inline\": true
                },
                {
                    \"name\": \"🕐 Timestamp\",
                    \"value\": \"$(date -u +'%Y-%m-%d %H:%M:%S UTC')\",
                    \"inline\": true
                }
            ],
            \"description\": \"${REPORT_DATA}\",
            \"footer\": {
                \"text\": \"Shopsifu Production Health Monitor\"
            },
            \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
        }]
    }"

    # Send to Discord with retry logic
    for i in $(seq 1 $MAX_RETRIES); do
        if curl -s -H "Content-Type: application/json" -X POST -d "$embed_json" "$DISCORD_WEBHOOK"; then
            echo -e "${GREEN}✅ Discord notification sent successfully${NC}"
            break
        else
            echo -e "${YELLOW}⚠️ Attempt $i/$MAX_RETRIES failed${NC}"
            if [ $i -lt $MAX_RETRIES ]; then
                sleep 2
            else
                echo -e "${RED}❌ Failed to send Discord notification after $MAX_RETRIES attempts${NC}"
            fi
        fi
    done
}

# Main execution
main() {
    echo -e "${CYAN}🚀 Starting comprehensive health check...${NC}"
    echo -e "${CYAN}📍 VPS Path: ${VPS_PATH}${NC}"

    # Change to correct directory
    cd "${VPS_PATH}" || {
        echo -e "${RED}❌ Failed to change to directory: ${VPS_PATH}${NC}"
        exit 1
    }

    # Perform all health checks
    check_service_health
    check_application_health
    check_database_health
    check_monitoring_health
    check_system_resources
    check_network_health
    check_recent_logs

    # Generate summary
    echo -e "${CYAN}📊 Health Check Summary:${NC}"
    echo -e "Overall Status: ${OVERALL_STATUS^^}"
    echo -e "Errors: ${ERROR_COUNT}"
    echo -e "Warnings: ${WARNING_COUNT}"

    # Send Discord notification
    send_discord_notification

    # Exit with appropriate code
    if [ "$OVERALL_STATUS" = "unhealthy" ]; then
        echo -e "${RED}❌ Health check completed with errors${NC}"
        exit 1
    elif [ "$WARNING_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}⚠️ Health check completed with warnings${NC}"
        exit 0
    else
        echo -e "${GREEN}✅ Health check completed successfully${NC}"
        exit 0
    fi
}

# Run main function
main "$@"
