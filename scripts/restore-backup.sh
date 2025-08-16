#!/bin/bash

# ==============================================
# RESTORE BACKUP SCRIPT FOR SHOPSIFU
# ==============================================

set -euo pipefail

# Configuration
BACKUP_PATH="/backup/shopsifu"
PROJECT_PATH="/home/tedydev/shopsifu/server-shopsifu"

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
    log_error "Backup directory does not exist: $BACKUP_PATH"
    exit 1
fi

# Function: List available backups
list_backups() {
    log_info "Available backups:"
    echo ""

    # List database backups
    if [ -d "$BACKUP_PATH/database" ]; then
        echo "📊 Database Backups:"
        ls -la "$BACKUP_PATH/database"/*.backup 2>/dev/null | while read -r line; do
            echo "  $line"
        done || echo "  No database backups found"
        echo ""
    fi

    # List file backups
    if [ -d "$BACKUP_PATH/files" ]; then
        echo "📁 File Backups:"
        ls -la "$BACKUP_PATH/files"/*.tar.gz 2>/dev/null | while read -r line; do
            echo "  $line"
        done || echo "  No file backups found"
        echo ""
    fi

    # List config backups
    if [ -d "$BACKUP_PATH/config" ]; then
        echo "⚙️ Config Backups:"
        ls -la "$BACKUP_PATH/config"/*.tar.gz 2>/dev/null | while read -r line; do
            echo "  $line"
        done || echo "  No config backups found"
        echo ""
    fi

    # List manifests
    echo "📋 Backup Manifests:"
    ls -la "$BACKUP_PATH"/*.manifest 2>/dev/null | while read -r line; do
        echo "  $line"
    done || echo "  No manifests found"
}

# Function: Show backup details
show_backup_details() {
    local backup_timestamp=$1

    log_info "Backup details for timestamp: $backup_timestamp"

    # Check manifest
    if [ -f "$BACKUP_PATH/shopsifu_backup_$backup_timestamp.manifest" ]; then
        echo ""
        echo "📋 Backup Manifest:"
        cat "$BACKUP_PATH/shopsifu_backup_$backup_timestamp.manifest"
    else
        log_warning "No manifest found for timestamp: $backup_timestamp"
    fi

    # Check backup files
    echo ""
    echo "📊 Backup Files:"

    if [ -f "$BACKUP_PATH/database/shopsifu_$backup_timestamp.backup" ]; then
        echo "  ✅ Database: shopsifu_$backup_timestamp.backup"
        echo "     Size: $(du -h "$BACKUP_PATH/database/shopsifu_$backup_timestamp.backup" | cut -f1)"
    else
        echo "  ❌ Database: Not found"
    fi

    if [ -f "$BACKUP_PATH/files/shopsifu_files_$backup_timestamp.tar.gz" ]; then
        echo "  ✅ Files: shopsifu_files_$backup_timestamp.tar.gz"
        echo "     Size: $(du -h "$BACKUP_PATH/files/shopsifu_files_$backup_timestamp.tar.gz" | cut -f1)"
    else
        echo "  ❌ Files: Not found"
    fi

    if [ -f "$BACKUP_PATH/config/shopsifu_config_$backup_timestamp.tar.gz" ]; then
        echo "  ✅ Config: shopsifu_config_$backup_timestamp.tar.gz"
        echo "     Size: $(du -h "$BACKUP_PATH/config/shopsifu_config_$backup_timestamp.tar.gz" | cut -f1)"
    else
        echo "  ❌ Config: Not found"
    fi
}

# Function: Restore database
restore_database() {
    local backup_timestamp=$1

    log_info "Restoring database from backup: $backup_timestamp"

    # Check if backup file exists
    if [ ! -f "$BACKUP_PATH/database/shopsifu_$backup_timestamp.backup" ]; then
        log_error "Database backup file not found: shopsifu_$backup_timestamp.backup"
        return 1
    fi

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

    # Copy backup to container
    docker cp "$BACKUP_PATH/database/shopsifu_$backup_timestamp.backup" "$CONTAINER_NAME:/tmp/"

    # Restore database
    log_warning "This will overwrite the current database. Are you sure? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        docker exec "$CONTAINER_NAME" pg_restore -U shopsifu -d shopsifu --clean --if-exists "/tmp/shopsifu_$backup_timestamp.backup"
        log_success "Database restored successfully"
    else
        log_info "Database restore cancelled"
        return 1
    fi
}

# Function: Restore files
restore_files() {
    local backup_timestamp=$1

    log_info "Restoring files from backup: $backup_timestamp"

    # Check if backup file exists
    if [ ! -f "$BACKUP_PATH/files/shopsifu_files_$backup_timestamp.tar.gz" ]; then
        log_error "Files backup file not found: shopsifu_files_$backup_timestamp.tar.gz"
        return 1
    fi

    # Change to project directory
    cd "$PROJECT_PATH" || {
        log_error "Cannot change to project directory: $PROJECT_PATH"
        return 1
    }

    # Create backup of current files
    CURRENT_BACKUP="current_files_$(date +%Y%m%d_%H%M%S).tar.gz"
    tar -czf "/tmp/$CURRENT_BACKUP" --exclude=node_modules --exclude=.git --exclude=dist --exclude=logs --exclude=backup .
    log_info "Current files backed up to: /tmp/$CURRENT_BACKUP"

    # Restore files
    log_warning "This will overwrite current files. Are you sure? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        tar -xzf "$BACKUP_PATH/files/shopsifu_files_$backup_timestamp.tar.gz"
        log_success "Files restored successfully"
    else
        log_info "Files restore cancelled"
        return 1
    fi
}

# Function: Restore configuration
restore_config() {
    local backup_timestamp=$1

    log_info "Restoring configuration from backup: $backup_timestamp"

    # Check if backup file exists
    if [ ! -f "$BACKUP_PATH/config/shopsifu_config_$backup_timestamp.tar.gz" ]; then
        log_error "Config backup file not found: shopsifu_config_$backup_timestamp.tar.gz"
        return 1
    fi

    # Change to project directory
    cd "$PROJECT_PATH" || {
        log_error "Cannot change to project directory: $PROJECT_PATH"
        return 1
    }

    # Create backup of current config
    CURRENT_CONFIG_BACKUP="current_config_$(date +%Y%m%d_%H%M%S).tar.gz"
    tar -czf "/tmp/$CURRENT_CONFIG_BACKUP" config/ monitoring/ .env.docker docker-compose.swarm.yml Dockerfile
    log_info "Current config backed up to: /tmp/$CURRENT_CONFIG_BACKUP"

    # Restore config
    log_warning "This will overwrite current configuration. Are you sure? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        tar -xzf "$BACKUP_PATH/config/shopsifu_config_$backup_timestamp.tar.gz"
        log_success "Configuration restored successfully"
    else
        log_info "Configuration restore cancelled"
        return 1
    fi
}

# Function: Full restore
full_restore() {
    local backup_timestamp=$1

    log_info "Starting full restore from backup: $backup_timestamp"

    # Show backup details
    show_backup_details "$backup_timestamp"

    # Confirm restore
    log_warning "This will perform a FULL RESTORE. All current data will be overwritten!"
    log_warning "Are you absolutely sure? Type 'RESTORE' to confirm:"
    read -r confirmation

    if [ "$confirmation" != "RESTORE" ]; then
        log_info "Full restore cancelled"
        return 1
    fi

    # Stop services
    log_info "Stopping Docker Swarm services..."
    docker stack rm shopsifu || true
    sleep 30

    # Restore database
    restore_database "$backup_timestamp"

    # Restore files
    restore_files "$backup_timestamp"

    # Restore configuration
    restore_config "$backup_timestamp"

    # Restart services
    log_info "Restarting Docker Swarm services..."
    ./scripts/deploy-swarm.sh

    log_success "Full restore completed successfully!"
}

# Function: Interactive restore
interactive_restore() {
    echo ""
    log_info "Restore Options:"
    echo "1. List available backups"
    echo "2. Show backup details"
    echo "3. Restore database only"
    echo "4. Restore files only"
    echo "5. Restore configuration only"
    echo "6. Full restore (everything)"
    echo "7. Exit"
    echo ""

    read -p "Choose an option (1-7): " choice

    case $choice in
        1)
            list_backups
            ;;
        2)
            read -p "Enter backup timestamp (e.g., 20241201_143022): " timestamp
            show_backup_details "$timestamp"
            ;;
        3)
            read -p "Enter backup timestamp (e.g., 20241201_143022): " timestamp
            restore_database "$timestamp"
            ;;
        4)
            read -p "Enter backup timestamp (e.g., 20241201_143022): " timestamp
            restore_files "$timestamp"
            ;;
        5)
            read -p "Enter backup timestamp (e.g., 20241201_143022): " timestamp
            restore_config "$timestamp"
            ;;
        6)
            read -p "Enter backup timestamp (e.g., 20241201_143022): " timestamp
            full_restore "$timestamp"
            ;;
        7)
            log_info "Exiting..."
            exit 0
            ;;
        *)
            log_error "Invalid option. Please choose 1-7."
            ;;
    esac
}

# Main function
main() {
    log_info "ShopSifu Backup Restore Tool"
    log_info "============================"

    # Check arguments
    if [ $# -eq 0 ]; then
        interactive_restore
    elif [ $# -eq 2 ]; then
        case $1 in
            --list)
                list_backups
                ;;
            --details)
                show_backup_details "$2"
                ;;
            --restore-db)
                restore_database "$2"
                ;;
            --restore-files)
                restore_files "$2"
                ;;
            --restore-config)
                restore_config "$2"
                ;;
            --full-restore)
                full_restore "$2"
                ;;
            *)
                log_error "Invalid option. Use --help for usage information."
                exit 1
                ;;
        esac
    else
        echo "Usage: $0 [OPTION] [TIMESTAMP]"
        echo ""
        echo "Options:"
        echo "  --list                    List available backups"
        echo "  --details TIMESTAMP       Show backup details"
        echo "  --restore-db TIMESTAMP    Restore database only"
        echo "  --restore-files TIMESTAMP Restore files only"
        echo "  --restore-config TIMESTAMP Restore configuration only"
        echo "  --full-restore TIMESTAMP  Full restore (everything)"
        echo ""
        echo "Examples:"
        echo "  $0 --list"
        echo "  $0 --details 20241201_143022"
        echo "  $0 --full-restore 20241201_143022"
        echo ""
        echo "If no arguments provided, interactive mode will be used."
        exit 1
    fi
}

# Run main function
main "$@"
