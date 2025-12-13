#!/bin/bash

# ShopSifu Server Setup Script
# This script automates the initial setup process for a new server

set -e  # Exit on error

echo "🚀 ShopSifu Server Setup Script"
echo "================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then
   echo -e "${RED}❌ Please do not run this script as root${NC}"
   exit 1
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}⚠️  Docker not found. Installing Docker...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    echo -e "${GREEN}✅ Docker installed. Please logout and login again, then run this script again.${NC}"
    exit 0
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${YELLOW}⚠️  Docker Compose not found. Installing Docker Compose...${NC}"
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo -e "${GREEN}✅ Docker Compose installed${NC}"
fi

# Check Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ Node.js not found. Please install Node.js 18.x or 20.x first${NC}"
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo -e "${RED}❌ Node.js version must be 18.x or higher. Current: $(node -v)${NC}"
    exit 1
fi

# Check npm
if ! command -v npm &> /dev/null; then
    echo -e "${RED}❌ npm not found${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Prerequisites check passed${NC}"
echo ""

# Get project directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "📦 Installing npm dependencies..."
npm install

echo ""
echo "🐳 Starting core services (PostgreSQL, Redis, Elasticsearch)..."
docker-compose -f docker-compose.core.yml up -d

echo ""
echo "⏳ Waiting for services to be ready (30 seconds)..."
sleep 30

echo ""
echo "🔍 Checking service health..."

# Check PostgreSQL
if docker exec shopsifu_postgres pg_isready -U shopsifu > /dev/null 2>&1; then
    echo -e "${GREEN}✅ PostgreSQL is ready${NC}"
else
    echo -e "${YELLOW}⚠️  PostgreSQL is not ready yet. Please check logs: docker logs shopsifu_postgres${NC}"
fi

# Check Redis
if docker exec shopsifu_redis redis-cli -a Shopsifu2025 PING > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Redis is ready${NC}"
else
    echo -e "${YELLOW}⚠️  Redis is not ready yet. Please check logs: docker logs shopsifu_redis${NC}"
fi

# Check Elasticsearch
if curl -s http://localhost:9200/_cluster/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Elasticsearch is ready${NC}"
else
    echo -e "${YELLOW}⚠️  Elasticsearch is not ready yet. Please check logs: docker logs shopsifu_elasticsearch${NC}"
fi

echo ""
echo "🗄️  Setting up database..."

echo "  → Generating Prisma Client..."
npm run generate

echo "  → Running migrations..."
npm run migrate

echo ""
read -p "Do you want to seed initial data? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "  → Seeding initial data..."
    npm run seed
    echo -e "${GREEN}✅ Database seeded${NC}"
else
    echo -e "${YELLOW}⚠️  Skipping seed. Run 'npm run seed' manually later if needed.${NC}"
fi

echo ""
echo "🏗️  Building application..."
npm run build

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}✅ Setup completed successfully!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "Next steps:"
echo "1. Review and update .env file if needed"
echo "2. Start the application:"
echo "   - With PM2: pm2 start ecosystem.config.js"
echo "   - Directly: npm start"
echo "   - Development: npm run dev"
echo ""
echo "3. (Optional) Start monitoring services:"
echo "   docker-compose -f docker-compose.monitoring.yml up -d"
echo ""
echo "4. (Optional) Setup Nginx and SSL certificates"
echo ""

