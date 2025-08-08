#!/bin/bash

# Script validate environment variables
# Chạy với: bash scripts/validate-env.sh

set -e

echo "🔍 Validate environment variables..."

# 1. Kiểm tra file .env.docker
if [ ! -f ".env.docker" ]; then
    echo "❌ File .env.docker không tồn tại!"
    exit 1
fi

echo "✅ File .env.docker tồn tại"

# 2. Load environment variables
source .env.docker

# 3. Kiểm tra các biến quan trọng
echo ""
echo "📋 Kiểm tra các biến quan trọng:"

# Database
echo "Database:"
echo "  POSTGRES_USER: ${POSTGRES_USER:-'NOT SET'}"
echo "  POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-'NOT SET'}"
echo "  POSTGRES_DB: ${POSTGRES_DB:-'NOT SET'}"
echo "  POSTGRES_PORT: ${POSTGRES_PORT:-'NOT SET'}"

# Redis
echo "Redis:"
echo "  REDIS_HOST: ${REDIS_HOST:-'NOT SET'}"
echo "  REDIS_PORT: ${REDIS_PORT:-'NOT SET'}"
echo "  REDIS_MAXMEMORY: ${REDIS_MAXMEMORY:-'NOT SET'}"

# Elasticsearch
echo "Elasticsearch:"
echo "  ELASTICSEARCH_NODE: ${ELASTICSEARCH_NODE:-'NOT SET'}"
echo "  ELASTICSEARCH_HEAP_SIZE: ${ELASTICSEARCH_HEAP_SIZE:-'NOT SET'}"

# Grafana
echo "Grafana:"
echo "  GRAFANA_ADMIN_USER: ${GRAFANA_ADMIN_USER:-'NOT SET'}"
echo "  GRAFANA_ADMIN_PASSWORD: ${GRAFANA_ADMIN_PASSWORD:-'NOT SET'}"
echo "  GRAFANA_PORT: ${GRAFANA_PORT:-'NOT SET'}"

# PgBouncer
echo "PgBouncer:"
echo "  PGBOUNCER_PORT: ${PGBOUNCER_PORT:-'NOT SET'}"
echo "  PGBOUNCER_POOL_MODE: ${PGBOUNCER_POOL_MODE:-'NOT SET'}"

# Nginx
echo "Nginx:"
echo "  NGINX_HTTP_PORT: ${NGINX_HTTP_PORT:-'NOT SET'}"
echo "  NGINX_HTTPS_PORT: ${NGINX_HTTPS_PORT:-'NOT SET'}"

# 4. Kiểm tra port conflicts
echo ""
echo "🔍 Kiểm tra port conflicts..."

ports=(
    "$POSTGRES_PORT:5432"
    "$REDIS_PORT:6379"
    "$ELASTICSEARCH_PORT:9200"
    "$KIBANA_PORT:5601"
    "$GRAFANA_PORT:3000"
    "$PGBOUNCER_PORT:5432"
    "$NGINX_HTTP_PORT:80"
    "$NGINX_HTTPS_PORT:443"
)

for port in "${ports[@]}"; do
    host_port=$(echo $port | cut -d: -f1)
    if [ "$host_port" != "127.0.0.1" ] && [ "$host_port" != "0.0.0.0" ]; then
        if netstat -tuln 2>/dev/null | grep -q ":$host_port "; then
            echo "⚠️  Port $host_port đang được sử dụng"
        else
            echo "✅ Port $host_port available"
        fi
    fi
done

# 5. Kiểm tra required files
echo ""
echo "📁 Kiểm tra required files:"

required_files=(
    "docker-compose.yml"
    ".env.docker"
    "nginx/nginx.conf"
    "nginx/conf.d/api.conf"
    "nginx/conf.d/grafana.conf"
    "nginx/conf.d/prometheus.conf"
)

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file - MISSING"
    fi
done

# 6. Kiểm tra SSL certificates
echo ""
echo "🔐 Kiểm tra SSL certificates:"

ssl_dirs=("api" "grafana" "prometheus")
for dir in "${ssl_dirs[@]}"; do
    if [ -d "nginx/ssl/$dir" ]; then
        if [ -f "nginx/ssl/$dir/fullchain.pem" ] && [ -f "nginx/ssl/$dir/privkey.pem" ]; then
            echo "✅ nginx/ssl/$dir - OK"
        else
            echo "⚠️  nginx/ssl/$dir - Missing certificates"
        fi
    else
        echo "❌ nginx/ssl/$dir - Directory missing"
    fi
done

# 7. Tóm tắt
echo ""
echo "📋 Tóm tắt:"
echo "- Environment file: ✅"
echo "- Required files: $(find . -name "docker-compose.yml" -o -name ".env.docker" -o -name "nginx.conf" | wc -l)/3"
echo "- SSL certificates: $(find nginx/ssl -name "fullchain.pem" 2>/dev/null | wc -l)/3"
echo "- Port conflicts: $(netstat -tuln 2>/dev/null | grep -E ":(80|443|5432|6379|9200|5601|3000|6432) " | wc -l)"

echo ""
echo "🚀 Để deploy:"
echo "docker compose up -d"
echo ""
echo "🔍 Để kiểm tra logs:"
echo "docker compose logs -f"
