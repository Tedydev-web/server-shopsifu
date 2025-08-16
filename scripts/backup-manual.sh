#!/bin/bash

# ==============================================
# MANUAL BACKUP SCRIPT FOR SHOPSIFU
# ==============================================

set -euo pipefail

# Configuration
BACKUP_PATH="/backup/shopsifu"
PROJECT_PATH="/home/tedydev/shopsifu/server-shopsifu"
RETENTION_DAYS=3

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
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

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    log_error "Please do not run as root"
    exit 1
fi

# Check if backup directory exists
if [ ! -d "$BACKUP_PATH" ]; then
    log_info "Creating backup directory: $BACKUP_PATH"
    sudo mkdir -p "$BACKUP_PATH"/{database,files,config,logs}
    sudo chown -R $USER:$USER "$BACKUP_PATH"
fi

# Create timestamp for backup
BACKUP_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
log_info "Starting backup with timestamp: $BACKUP_TIMESTAMP"

# Change to project directory
cd "$PROJECT_PATH" || {
    log_error "Cannot change to project directory: $PROJECT_PATH"
    exit 1
}

# Function: Backup PostgreSQL Database
backup_database() {
    log_info "Backing up PostgreSQL database..."

    # Check if PostgreSQL container is running
    if ! docker ps | grep -q "shopsifu_postgres"; then
        log_error "PostgreSQL container is not running"
        return 1
    fi

    # Get container name
    CONTAINER_NAME=$(docker ps --filter "name=shopsifu_postgres" --format "{{.Names}}" | head -1)

    if [ -z "$CONTAINER_NAME" ]; then
        log_error "Cannot find PostgreSQL container"
        return 1
    fi

    # Create database backup
    docker exec "$CONTAINER_NAME" pg_dump -U shopsifu -d shopsifu --format=custom --file="/tmp/shopsifu_$BACKUP_TIMESTAMP.backup"

    # Copy backup from container
    docker cp "$CONTAINER_NAME:/tmp/shopsifu_$BACKUP_TIMESTAMP.backup" "$BACKUP_PATH/database/"

    # Verify backup file
    if [ -f "$BACKUP_PATH/database/shopsifu_$BACKUP_TIMESTAMP.backup" ]; then
        BACKUP_SIZE=$(du -h "$BACKUP_PATH/database/shopsifu_$BACKUP_TIMESTAMP.backup" | cut -f1)
        log_success "Database backup completed: shopsifu_$BACKUP_TIMESTAMP.backup ($BACKUP_SIZE)"
    else
        log_error "Database backup failed"
        return 1
    fi
}

# Function: Backup Application Files
backup_files() {
    log_info "Backing up application files..."

    # Create files backup
    tar -czf "$BACKUP_PATH/files/shopsifu_files_$BACKUP_TIMESTAMP.tar.gz" \
        --exclude=node_modules \
        --exclude=.git \
        --exclude=dist \
        --exclude=logs \
        --exclude=backup \
        --exclude=uploads \
        .

    # Verify backup file
    if [ -f "$BACKUP_PATH/files/shopsifu_files_$BACKUP_TIMESTAMP.tar.gz" ]; then
        BACKUP_SIZE=$(du -h "$BACKUP_PATH/files/shopsifu_files_$BACKUP_TIMESTAMP.tar.gz" | cut -f1)
        log_success "Files backup completed: shopsifu_files_$BACKUP_TIMESTAMP.tar.gz ($BACKUP_SIZE)"
    else
        log_error "Files backup failed"
        return 1
    fi
}

# Function: Backup Configuration Files
backup_config() {
    log_info "Backing up configuration files..."

    # Create config backup
    tar -czf "$BACKUP_PATH/config/shopsifu_config_$BACKUP_TIMESTAMP.tar.gz" \
        config/ \
        monitoring/ \
        .env.docker \
        docker-compose.swarm.yml \
        Dockerfile \
        scripts/

    # Verify backup file
    if [ -f "$BACKUP_PATH/config/shopsifu_config_$BACKUP_TIMESTAMP.tar.gz" ]; then
        BACKUP_SIZE=$(du -h "$BACKUP_PATH/config/shopsifu_config_$BACKUP_TIMESTAMP.tar.gz" | cut -f1)
        log_success "Config backup completed: shopsifu_config_$BACKUP_TIMESTAMP.tar.gz ($BACKUP_SIZE)"
    else
        log_error "Config backup failed"
        return 1
    fi
}

# Function: Backup Docker Volumes
backup_volumes() {
    log_info "Backing up Docker volumes..."

    # Check if Docker Swarm stack is running
    if ! docker stack ls | grep -q "shopsifu"; then
        log_warning "Docker Swarm stack 'shopsifu' is not running, skipping volume backup"
        return 0
    fi

    # Stop services temporarily for consistent backup
    log_info "Stopping services for consistent backup..."
    docker stack rm shopsifu || true
    sleep 30

    # Backup PostgreSQL data volume
    if docker volume ls | grep -q "postgres_data"; then
        docker run --rm -v postgres_data:/data -v "$BACKUP_PATH/database:/backup" \
            alpine tar -czf "/backup/postgres_data_$BACKUP_TIMESTAMP.tar.gz" -C /data .
        log_success "PostgreSQL data volume backup completed"
    fi

    # Backup Redis data volume
    if docker volume ls | grep -q "redis_data"; then
        docker run --rm -v redis_data:/data -v "$BACKUP_PATH/database:/backup" \
            alpine tar -czf "/backup/redis_data_$BACKUP_TIMESTAMP.tar.gz" -C /data .
        log_success "Redis data volume backup completed"
    fi

    # Backup Elasticsearch data volume
    if docker volume ls | grep -q "esdata"; then
        docker run --rm -v esdata:/data -v "$BACKUP_PATH/database:/backup" \
            alpine tar -czf "/backup/elasticsearch_data_$BACKUP_TIMESTAMP.tar.gz" -C /data .
        log_success "Elasticsearch data volume backup completed"
    fi

    # Restart services
    log_info "Restarting services..."
    ./scripts/deploy-swarm.sh

    log_success "Docker volumes backup completed"
}

# Function: Create Backup Manifest
create_manifest() {
    log_info "Creating backup manifest..."

    # Create manifest file
    cat > "$BACKUP_PATH/shopsifu_backup_$BACKUP_TIMESTAMP.manifest" << EOF
ShopSifu System Backup Manifest
=================================

Backup Timestamp: $BACKUP_TIMESTAMP
Backup Date: $(date)
System: $(uname -a)
Docker Version: $(docker --version)
User: $USER
Project Path: $PROJECT_PATH

Backup Contents:
- Database: shopsifu_$BACKUP_TIMESTAMP.backup
- Files: shopsifu_files_$BACKUP_TIMESTAMP.tar.gz
- Config: shopsifu_config_$BACKUP_TIMESTAMP.tar.gz
- PostgreSQL Data: postgres_data_$BACKUP_TIMESTAMP.tar.gz
- Redis Data: redis_data_$BACKUP_TIMESTAMP.tar.gz
- Elasticsearch Data: elasticsearch_data_$BACKUP_TIMESTAMP.tar.gz

Total Size: $(du -sh "$BACKUP_PATH" | cut -f1)

Backup Location: $BACKUP_PATH
Created by: Manual Script
EOF

    log_success "Backup manifest created: shopsifu_backup_$BACKUP_TIMESTAMP.manifest"
}

# Function: Cleanup Old Backups
cleanup_old_backups() {
    log_info "Cleaning up old backups (older than $RETENTION_DAYS days)..."

    # Remove old backups
    find "$BACKUP_PATH" -name "*.backup" -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_PATH" -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_PATH" -name "*.manifest" -mtime +$RETENTION_DAYS -delete

    log_success "Cleaned up backups older than $RETENTION_DAYS days"

    # Show current backup status
    log_info "Current backup status:"
    du -sh "$BACKUP_PATH"/*
    log_info "Total backup size: $(du -sh "$BACKUP_PATH" | cut -f1)"
}

# Function: Show Backup Status
show_backup_status() {
    log_info "Backup completed successfully!"
    log_info "Backup timestamp: $BACKUP_TIMESTAMP"
    log_info "Backup location: $BACKUP_PATH"
    log_info "Backup size: $(du -sh "$BACKUP_PATH" | cut -f1)"

    echo ""
    log_info "Backup files created:"
    ls -la "$BACKUP_PATH"/*/*"$BACKUP_TIMESTAMP"* 2>/dev/null || true
}

# Main backup process
main() {
    log_info "Starting ShopSifu system backup..."

    # Create backup directories
    mkdir -p "$BACKUP_PATH"/{database,files,config,logs}

    # Perform backups
    backup_database
    backup_files
    backup_config
    backup_volumes

    # Create manifest
    create_manifest

    # Cleanup old backups
    cleanup_old_backups

    # Show final status
    show_backup_status

    log_success "Backup process completed successfully!"
}

# Run main function
main "$@"
