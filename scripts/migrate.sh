#!/bin/bash

# ShopSifu Server Migration Script
# This script helps migrate data from old server to new server

set -e  # Exit on error

echo "🔄 ShopSifu Server Migration Script"
echo "===================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get project directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="$PROJECT_DIR/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

echo "Select migration type:"
echo "1) Backup data from current server"
echo "2) Restore data to current server"
echo ""
read -p "Enter choice (1 or 2): " choice

case $choice in
    1)
        echo ""
        echo -e "${BLUE}📦 BACKUP MODE${NC}"
        echo "================"
        echo ""

        # Check if services are running
        if ! docker ps | grep -q shopsifu_postgres; then
            echo -e "${RED}❌ PostgreSQL container not running. Please start services first.${NC}"
            exit 1
        fi

        echo "Creating backups in: $BACKUP_DIR"
        echo ""

        # Backup PostgreSQL
        echo -e "${YELLOW}→ Backing up PostgreSQL...${NC}"
        docker exec shopsifu_postgres pg_dump -U shopsifu shopsifu > "$BACKUP_DIR/postgres_backup_$TIMESTAMP.sql"
        echo -e "${GREEN}✅ PostgreSQL backup created: postgres_backup_$TIMESTAMP.sql${NC}"

        # Backup Redis
        echo -e "${YELLOW}→ Backing up Redis...${NC}"
        docker exec shopsifu_redis redis-cli -a Shopsifu2025 SAVE > /dev/null 2>&1
        docker cp shopsifu_redis:/data/dump.rdb "$BACKUP_DIR/redis_backup_$TIMESTAMP.rdb" 2>/dev/null || echo -e "${YELLOW}⚠️  Redis backup skipped (no dump file)${NC}"
        if [ -f "$BACKUP_DIR/redis_backup_$TIMESTAMP.rdb" ]; then
            echo -e "${GREEN}✅ Redis backup created: redis_backup_$TIMESTAMP.rdb${NC}"
        fi

        # Backup Docker volumes (optional)
        read -p "Do you want to backup Docker volumes? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}→ Backing up Docker volumes...${NC}"

            # Backup PostgreSQL volume
            docker run --rm -v shopsifu_postgres_data:/data -v "$BACKUP_DIR":/backup alpine tar czf /backup/postgres_volume_$TIMESTAMP.tar.gz -C /data . 2>/dev/null || true
            if [ -f "$BACKUP_DIR/postgres_volume_$TIMESTAMP.tar.gz" ]; then
                echo -e "${GREEN}✅ PostgreSQL volume backup created${NC}"
            fi

            # Backup Redis volume
            docker run --rm -v shopsifu_redis_data:/data -v "$BACKUP_DIR":/backup alpine tar czf /backup/redis_volume_$TIMESTAMP.tar.gz -C /data . 2>/dev/null || true
            if [ -f "$BACKUP_DIR/redis_volume_$TIMESTAMP.tar.gz" ]; then
                echo -e "${GREEN}✅ Redis volume backup created${NC}"
            fi

            # Backup Elasticsearch volume
            docker run --rm -v shopsifu_elasticsearch_data:/data -v "$BACKUP_DIR":/backup alpine tar czf /backup/elasticsearch_volume_$TIMESTAMP.tar.gz -C /data . 2>/dev/null || true
            if [ -f "$BACKUP_DIR/elasticsearch_volume_$TIMESTAMP.tar.gz" ]; then
                echo -e "${GREEN}✅ Elasticsearch volume backup created${NC}"
            fi
        fi

        echo ""
        echo -e "${GREEN}================================${NC}"
        echo -e "${GREEN}✅ Backup completed!${NC}"
        echo -e "${GREEN}================================${NC}"
        echo ""
        echo "Backup files location: $BACKUP_DIR"
        echo ""
        echo "To transfer to new server, you can use:"
        echo "  scp $BACKUP_DIR/* user@new-server:/path/to/backups/"
        echo ""
        ;;

    2)
        echo ""
        echo -e "${BLUE}📥 RESTORE MODE${NC}"
        echo "================"
        echo ""

        # Check if backup directory exists
        if [ ! -d "$BACKUP_DIR" ] || [ -z "$(ls -A $BACKUP_DIR 2>/dev/null)" ]; then
            echo -e "${RED}❌ No backups found in $BACKUP_DIR${NC}"
            echo "Please copy backup files to this directory first."
            exit 1
        fi

        echo "Available backups in $BACKUP_DIR:"
        ls -lh "$BACKUP_DIR" | grep -E "\.(sql|rdb|tar\.gz)$" || echo "No backup files found"
        echo ""

        read -p "Enter PostgreSQL backup filename (or press Enter to skip): " postgres_backup
        if [ -n "$postgres_backup" ]; then
            if [ ! -f "$BACKUP_DIR/$postgres_backup" ]; then
                echo -e "${RED}❌ File not found: $BACKUP_DIR/$postgres_backup${NC}"
                exit 1
            fi

            echo -e "${YELLOW}⚠️  WARNING: This will replace all data in PostgreSQL!${NC}"
            read -p "Are you sure? (yes/no): " confirm
            if [ "$confirm" != "yes" ]; then
                echo "Restore cancelled."
                exit 0
            fi

            echo -e "${YELLOW}→ Restoring PostgreSQL...${NC}"
            # Drop and recreate database
            docker exec -i shopsifu_postgres psql -U shopsifu -d postgres -c "DROP DATABASE IF EXISTS shopsifu;"
            docker exec -i shopsifu_postgres psql -U shopsifu -d postgres -c "CREATE DATABASE shopsifu;"
            cat "$BACKUP_DIR/$postgres_backup" | docker exec -i shopsifu_postgres psql -U shopsifu -d shopsifu
            echo -e "${GREEN}✅ PostgreSQL restored${NC}"
        fi

        read -p "Enter Redis backup filename (or press Enter to skip): " redis_backup
        if [ -n "$redis_backup" ]; then
            if [ ! -f "$BACKUP_DIR/$redis_backup" ]; then
                echo -e "${RED}❌ File not found: $BACKUP_DIR/$redis_backup${NC}"
                exit 1
            fi

            echo -e "${YELLOW}→ Restoring Redis...${NC}"
            docker cp "$BACKUP_DIR/$redis_backup" shopsifu_redis:/data/dump.rdb
            docker restart shopsifu_redis
            echo -e "${GREEN}✅ Redis restored${NC}"
        fi

        read -p "Enter Docker volume backup prefix to restore (or press Enter to skip): " volume_prefix
        if [ -n "$volume_prefix" ]; then
            echo -e "${YELLOW}⚠️  WARNING: This will replace all data in volumes!${NC}"
            read -p "Are you sure? (yes/no): " confirm
            if [ "$confirm" != "yes" ]; then
                echo "Volume restore cancelled."
                exit 0
            fi

            # Stop services
            echo -e "${YELLOW}→ Stopping services...${NC}"
            docker-compose -f docker-compose.core.yml down

            # Restore volumes
            if [ -f "$BACKUP_DIR/${volume_prefix}postgres_volume_"*.tar.gz ]; then
                echo -e "${YELLOW}→ Restoring PostgreSQL volume...${NC}"
                docker run --rm -v shopsifu_postgres_data:/data -v "$BACKUP_DIR":/backup alpine sh -c "cd /data && rm -rf * && tar xzf /backup/${volume_prefix}postgres_volume_"*.tar.gz
            fi

            if [ -f "$BACKUP_DIR/${volume_prefix}redis_volume_"*.tar.gz ]; then
                echo -e "${YELLOW}→ Restoring Redis volume...${NC}"
                docker run --rm -v shopsifu_redis_data:/data -v "$BACKUP_DIR":/backup alpine sh -c "cd /data && rm -rf * && tar xzf /backup/${volume_prefix}redis_volume_"*.tar.gz
            fi

            if [ -f "$BACKUP_DIR/${volume_prefix}elasticsearch_volume_"*.tar.gz ]; then
                echo -e "${YELLOW}→ Restoring Elasticsearch volume...${NC}"
                docker run --rm -v shopsifu_elasticsearch_data:/data -v "$BACKUP_DIR":/backup alpine sh -c "cd /data && rm -rf * && tar xzf /backup/${volume_prefix}elasticsearch_volume_"*.tar.gz
            fi

            # Start services
            echo -e "${YELLOW}→ Starting services...${NC}"
            docker-compose -f docker-compose.core.yml up -d

            echo -e "${GREEN}✅ Volumes restored${NC}"
        fi

        echo ""
        echo -e "${GREEN}================================${NC}"
        echo -e "${GREEN}✅ Restore completed!${NC}"
        echo -e "${GREEN}================================${NC}"
        echo ""
        echo "If you restored PostgreSQL, you may need to run:"
        echo "  npm run generate"
        echo ""
        ;;

    *)
        echo -e "${RED}❌ Invalid choice${NC}"
        exit 1
        ;;
esac

