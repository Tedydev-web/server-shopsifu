#!/bin/bash

# 🚀 ShopSifu Monitoring Setup Script
# Tự động setup hệ thống monitoring chuyên nghiệp

set -e

echo "=============================================="
echo "    ShopSifu Monitoring Setup Script"
echo "=============================================="

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

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root"
   exit 1
fi

# Check if Docker is running
print_status "Checking Docker status..."
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker first."
    exit 1
fi
print_success "Docker is running"

# Check if docker-compose is available
print_status "Checking docker-compose availability..."
if ! command -v docker compose &> /dev/null; then
    print_error "docker-compose is not available. Please install it first."
    exit 1
fi
print_success "docker-compose is available"

# Check if .env.docker exists
print_status "Checking environment configuration..."
if [[ ! -f ".env.docker" ]]; then
    print_error ".env.docker file not found. Please create it with required environment variables."
    exit 1
fi
print_success ".env.docker file found"

# Create monitoring directories if they don't exist
print_status "Creating monitoring directory structure..."
mkdir -p monitoring/{prometheus,rules,alertmanager,blackbox,grafana/provisioning/{datasources,dashboards}}

# Set proper permissions
print_status "Setting proper permissions..."
sudo chown -R $(whoami):$(whoami) monitoring/
chmod -R 755 monitoring/

# Stop existing containers
print_status "Stopping existing containers..."
docker compose down --remove-orphans 2>/dev/null || true

# Pull latest images
print_status "Pulling latest Docker images..."
docker compose pull

# Start monitoring services
print_status "Starting monitoring services..."
docker compose up -d

# Wait for services to be ready
print_status "Waiting for services to be ready..."
sleep 30

# Check service status
print_status "Checking service status..."
docker compose ps

# Test monitoring endpoints
print_status "Testing monitoring endpoints..."

# Test Prometheus
if curl -s http://localhost:9090/api/v1/targets > /dev/null; then
    print_success "Prometheus is accessible"
else
    print_warning "Prometheus is not accessible yet"
fi

# Test Grafana
if curl -s http://localhost:3001/api/health > /dev/null; then
    print_success "Grafana is accessible"
else
    print_warning "Grafana is not accessible yet"
fi

# Test Alertmanager
if curl -s http://localhost:9093/api/v1/status > /dev/null; then
    print_success "Alertmanager is accessible"
else
    print_warning "Alertmanager is not accessible yet"
fi

# Test Redis Exporter
if curl -s http://localhost:9121/metrics > /dev/null; then
    print_success "Redis Exporter is accessible"
else
    print_warning "Redis Exporter is not accessible yet"
fi

# Test PostgreSQL Exporter
if curl -s http://localhost:9187/metrics > /dev/null; then
    print_success "PostgreSQL Exporter is accessible"
else
    print_warning "PostgreSQL Exporter is not accessible yet"
fi

# Wait a bit more for all services to be fully ready
print_status "Waiting for all services to be fully ready..."
sleep 30

# Final status check
print_status "Final status check..."
docker compose ps

# Display access information
echo ""
echo "=============================================="
echo "           MONITORING SETUP COMPLETE"
echo "=============================================="
echo ""
echo "🌐 Access URLs:"
echo "   Prometheus:     http://localhost:9090"
echo "   Grafana:        http://localhost:3001"
echo "   Alertmanager:   http://localhost:9093"
echo "   Redis Exporter: http://localhost:9121/metrics"
echo "   Postgres Exp:   http://localhost:9187/metrics"
echo ""
echo "🔧 Next Steps:"
echo "   1. Access Grafana at http://localhost:3001"
echo "   2. Default credentials: admin/admin"
echo "   3. Add Prometheus as data source: http://shopsifu_prometheus:9090"
echo "   4. Import dashboards or create new ones"
echo "   5. Configure alerting rules in Alertmanager"
echo ""
echo "📊 Test monitoring system:"
echo "   ./scripts/test-monitoring.sh"
echo ""
echo "🔄 Restart services:"
echo "   docker compose restart"
echo ""
echo "📋 View logs:"
echo "   docker compose logs -f [service_name]"
echo ""

print_success "Monitoring setup completed successfully!"
print_status "You can now access your monitoring dashboard at http://localhost:3001"

