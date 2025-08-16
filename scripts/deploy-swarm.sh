#!/bin/bash

# ==============================================
# DOCKER SWARM DEPLOYMENT SCRIPT FOR SHOPSIFU
# ==============================================

set -e

echo "🚀 Starting Docker Swarm deployment for ShopSifu..."

# ==============================================
# CHECK DOCKER SWARM STATUS
# ==============================================
echo "🔍 Checking Docker Swarm status..."

if ! docker info | grep -q "Swarm: active"; then
    echo "❌ Docker Swarm is not active. Initializing..."
    docker swarm init
    echo "✅ Docker Swarm initialized successfully!"
else
    echo "✅ Docker Swarm is already active."
fi

# ==============================================
# CHECK REQUIRED FILES
# ==============================================
echo "📁 Checking required files..."

REQUIRED_FILES=(
    "docker-compose.swarm.yml"
    ".env.docker"
    "config/elasticsearch.yml"
    "config/postgresql.conf"
    "config/redis.conf"
    "config/pgbouncer.ini"
    "config/userlist.txt"
    "monitoring/prometheus/server.yml"
    "monitoring/grafana/provisioning/datasources/grafana-datasource.yml"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "❌ Missing required file: $file"
        exit 1
    else
        echo "✅ Found: $file"
    fi
done

# ==============================================
# CREATE REQUIRED DIRECTORIES
# ==============================================
echo "📂 Creating required directories..."

mkdir -p logs certs upload monitoring/prometheus monitoring/grafana/provisioning/datasources

# ==============================================
# DEPLOY STACK
# ==============================================
echo "🚀 Deploying Docker Swarm stack..."

STACK_NAME="shopsifu"
COMPOSE_FILE="docker-compose.swarm.yml"

# Remove existing stack if exists
if docker stack ls | grep -q "$STACK_NAME"; then
    echo "🔄 Removing existing stack: $STACK_NAME"
    docker stack rm "$STACK_NAME"
    echo "⏳ Waiting for stack removal..."
    sleep 30
fi

# Deploy new stack
echo "🚀 Deploying new stack: $STACK_NAME"
docker stack deploy -c "$COMPOSE_FILE" "$STACK_NAME"

# ==============================================
# WAIT FOR SERVICES TO START
# ==============================================
echo "⏳ Waiting for services to start..."
sleep 60

# ==============================================
# CHECK SERVICE STATUS
# ==============================================
echo "📊 Checking service status..."

docker service ls

echo ""
echo "🔍 Checking individual service status..."

SERVICES=("postgres" "redis" "elasticsearch" "server" "pgbouncer" "prometheus" "grafana" "kibana")

for service in "${SERVICES[@]}"; do
    SERVICE_NAME="${STACK_NAME}_${service}"
    echo "📋 Service: $SERVICE_NAME"
    
    if docker service ls | grep -q "$SERVICE_NAME"; then
        REPLICAS=$(docker service ls --filter "name=$SERVICE_NAME" --format "{{.Replicas}}")
        echo "   Status: $REPLICAS"
    else
        echo "   Status: ❌ Not found"
    fi
done

# ==============================================
# HEALTH CHECK
# ==============================================
echo ""
echo "🏥 Performing health checks..."

# Wait a bit more for services to be ready
sleep 30

# Check server health
if curl -s http://localhost:3000/health > /dev/null 2>&1; then
    echo "✅ Server health check: OK"
else
    echo "❌ Server health check: FAILED"
fi

# Check Elasticsearch
if curl -s http://localhost:9200 > /dev/null 2>&1; then
    echo "✅ Elasticsearch health check: OK"
else
    echo "❌ Elasticsearch health check: FAILED"
fi

# Check Prometheus
if curl -s http://localhost:9090/-/healthy > /dev/null 2>&1; then
    echo "✅ Prometheus health check: OK"
else
    echo "❌ Prometheus health check: FAILED"
fi

# ==============================================
# DEPLOYMENT COMPLETE
# ==============================================
echo ""
echo "🎉 Deployment completed successfully!"
echo ""
echo "📊 Stack Information:"
echo "   Name: $STACK_NAME"
echo "   Services: $(docker service ls --filter "name=${STACK_NAME}_" -q | wc -l)"
echo ""
echo "🌐 Access URLs:"
echo "   Server: http://localhost:3000"
echo "   Prometheus: http://localhost:9090"
echo "   Grafana: http://localhost:3001 (admin/Shopsifu2025)"
echo "   Kibana: http://localhost:5601"
echo "   Elasticsearch: http://localhost:9200"
echo ""
echo "🔧 Management Commands:"
echo "   View services: docker service ls"
echo "   View logs: docker service logs ${STACK_NAME}_server"
echo "   Scale service: docker service scale ${STACK_NAME}_server=5"
echo "   Remove stack: docker stack rm $STACK_NAME"
