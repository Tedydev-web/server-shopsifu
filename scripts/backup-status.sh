#!/bin/bash

# ==============================================
# BACKUP STATUS CHECK SCRIPT FOR SHOPSIFU
# ==============================================

set -euo pipefail

# Configuration
BACKUP_PATH="/backup/shopsifu"
RETENTION_DAYS=3

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
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

log_header() {
    echo -e "${PURPLE}[HEADER]${NC} $1"
}

log_detail() {
    echo -e "${CYAN}[DETAIL]${NC} $1"
}

# Check if backup directory exists
if [ ! -d "$BACKUP_PATH" ]; then
    log_error "Backup directory does not exist: $BACKUP_PATH"
    exit 1
fi

# Function: Check disk usage
check_disk_usage() {
    log_header "💾 DISK USAGE ANALYSIS"

    # Get backup directory size
    BACKUP_SIZE=$(du -sh "$BACKUP_PATH" | cut -f1)
    BACKUP_SIZE_BYTES=$(du -sb "$BACKUP_PATH" | cut -f1)

    # Get disk usage for backup partition
    DISK_INFO=$(df "$BACKUP_PATH" | tail -1)
    DISK_TOTAL=$(echo "$DISK_INFO" | awk '{print $2}')
    DISK_USED=$(echo "$DISK_INFO" | awk '{print $3}')
    DISK_AVAIL=$(echo "$DISK_INFO" | awk '{print $4}')
    DISK_USAGE_PERCENT=$(echo "$DISK_INFO" | awk '{print $5}' | sed 's/%//')

    # Convert to human readable
    DISK_TOTAL_HR=$(numfmt --to=iec-i --suffix=B $((DISK_TOTAL * 1024)))
    DISK_USED_HR=$(numfmt --to=iec-i --suffix=B $((DISK_USED * 1024)))
    DISK_AVAIL_HR=$(numfmt --to=iec-i --suffix=B $((DISK_AVAIL * 1024)))

    echo "📊 Backup Directory Size: $BACKUP_SIZE"
    echo "💿 Total Disk Space: $DISK_TOTAL_HR"
    echo "🔴 Used Disk Space: $DISK_USED_HR"
    echo "🟢 Available Disk Space: $DISK_AVAIL_HR"
    echo "📈 Disk Usage: $DISK_USAGE_PERCENT%"

    # Warning if disk usage is high
    if [ "$DISK_USAGE_PERCENT" -gt 80 ]; then
        log_warning "⚠️  Disk usage is high (>80%)"
    elif [ "$DISK_USAGE_PERCENT" -gt 90 ]; then
        log_error "🚨 Disk usage is critical (>90%)"
    else
        log_success "✅ Disk usage is healthy"
    fi

    echo ""
}

# Function: List backup files by type
list_backups_by_type() {
    log_header "🗄️ BACKUP FILES BY TYPE"

    # Database backups
    if [ -d "$BACKUP_PATH/database" ]; then
        echo "📊 Database Backups:"
        if ls "$BACKUP_PATH/database"/*.backup 1> /dev/null 2>&1; then
            ls -lah "$BACKUP_PATH/database"/*.backup | while read -r line; do
                echo "  $line"
            done
        else
            echo "  No database backups found"
        fi
        echo ""
    fi

    # File backups
    if [ -d "$BACKUP_PATH/files" ]; then
        echo "📁 File Backups:"
        if ls "$BACKUP_PATH/files"/*.tar.gz 1> /dev/null 2>&1; then
            ls -lah "$BACKUP_PATH/files"/*.tar.gz | while read -r line; do
                echo "  $line"
            done
        else
            echo "  No file backups found"
        fi
        echo ""
    fi

    # Config backups
    if [ -d "$BACKUP_PATH/config" ]; then
        echo "⚙️ Config Backups:"
        if ls "$BACKUP_PATH/config"/*.tar.gz 1> /dev/null 2>&1; then
            ls -lah "$BACKUP_PATH/config"/*.tar.gz | while read -r line; do
                echo "  $line"
            done
        else
            echo "  No config backups found"
        fi
        echo ""
    fi

    # Manifests
    echo "📋 Backup Manifests:"
    if ls "$BACKUP_PATH"/*.manifest 1> /dev/null 2>&1; then
        ls -lah "$BACKUP_PATH"/*.manifest | while read -r line; do
            echo "  $line"
        done
    else
        echo "  No manifests found"
    fi
    echo ""
}

# Function: Check backup age and retention
check_backup_age() {
    log_header "⏰ BACKUP AGE & RETENTION ANALYSIS"

    echo "📅 Retention Policy: $RETENTION_DAYS days"
    echo "🧹 Backups older than $RETENTION_DAYS days will be automatically cleaned up"
    echo ""

    # Check database backups age
    if [ -d "$BACKUP_PATH/database" ]; then
        echo "📊 Database Backup Ages:"
        if ls "$BACKUP_PATH/database"/*.backup 1> /dev/null 2>&1; then
            for backup in "$BACKUP_PATH/database"/*.backup; do
                if [ -f "$backup" ]; then
                    BACKUP_NAME=$(basename "$backup")
                    BACKUP_AGE=$(find "$backup" -printf '%AY-%Am-%Ad %AH:%AM\n' 2>/dev/null || stat -c %y "$backup" | cut -d' ' -f1,2)
                    BACKUP_DAYS_OLD=$(find "$backup" -mtime +0 -printf '%Ad\n' 2>/dev/null || echo "0")

                    if [ "$BACKUP_DAYS_OLD" -gt "$RETENTION_DAYS" ]; then
                        echo "  🔴 $BACKUP_NAME - $BACKUP_AGE (OLD - will be cleaned up)"
                    else
                        echo "  🟢 $BACKUP_NAME - $BACKUP_AGE"
                    fi
                fi
            done
        else
            echo "  No database backups found"
        fi
        echo ""
    fi

    # Check file backups age
    if [ -d "$BACKUP_PATH/files" ]; then
        echo "📁 File Backup Ages:"
        if ls "$BACKUP_PATH/files"/*.tar.gz 1> /dev/null 2>&1; then
            for backup in "$BACKUP_PATH/files"/*.tar.gz; do
                if [ -f "$backup" ]; then
                    BACKUP_NAME=$(basename "$backup")
                    BACKUP_AGE=$(find "$backup" -printf '%AY-%Am-%Ad %AH:%AM\n' 2>/dev/null || stat -c %y "$backup" | cut -d' ' -f1,2)
                    BACKUP_DAYS_OLD=$(find "$backup" -mtime +0 -printf '%Ad\n' 2>/dev/null || echo "0")

                    if [ "$BACKUP_DAYS_OLD" -gt "$RETENTION_DAYS" ]; then
                        echo "  🔴 $BACKUP_NAME - $BACKUP_AGE (OLD - will be cleaned up)"
                    else
                        echo "  🟢 $BACKUP_NAME - $BACKUP_AGE"
                    fi
                fi
            done
        else
            echo "  No file backups found"
        fi
        echo ""
    fi
}

# Function: Check backup integrity
check_backup_integrity() {
    log_header "🔍 BACKUP INTEGRITY CHECK"

    # Check if we have complete backup sets
    if [ -d "$BACKUP_PATH/database" ] && [ -d "$BACKUP_PATH/files" ] && [ -d "$BACKUP_PATH/config" ]; then
        echo "📊 Checking backup completeness..."

        # Get latest timestamp from database backups
        LATEST_DB=$(ls -t "$BACKUP_PATH/database"/*.backup 2>/dev/null | head -1)
        if [ -n "$LATEST_DB" ]; then
            LATEST_TIMESTAMP=$(basename "$LATEST_DB" | sed 's/shopsifu_\(.*\)\.backup/\1/')

            echo "🕐 Latest backup timestamp: $LATEST_TIMESTAMP"

            # Check if all components exist for this timestamp
            DB_BACKUP="$BACKUP_PATH/database/shopsifu_$LATEST_TIMESTAMP.backup"
            FILES_BACKUP="$BACKUP_PATH/files/shopsifu_files_$LATEST_TIMESTAMP.tar.gz"
            CONFIG_BACKUP="$BACKUP_PATH/config/shopsifu_config_$LATEST_TIMESTAMP.tar.gz"
            MANIFEST="$BACKUP_PATH/shopsifu_backup_$LATEST_TIMESTAMP.manifest"

            echo "📋 Backup Components:"
            if [ -f "$DB_BACKUP" ]; then
                echo "  ✅ Database: $(basename "$DB_BACKUP")"
            else
                echo "  ❌ Database: Missing"
            fi

            if [ -f "$FILES_BACKUP" ]; then
                echo "  ✅ Files: $(basename "$FILES_BACKUP")"
            else
                echo "  ❌ Files: Missing"
            fi

            if [ -f "$CONFIG_BACKUP" ]; then
                echo "  ✅ Config: $(basename "$CONFIG_BACKUP")"
            else
                echo "  ❌ Config: Missing"
            fi

            if [ -f "$MANIFEST" ]; then
                echo "  ✅ Manifest: $(basename "$MANIFEST")"
            else
                echo "  ❌ Manifest: Missing"
            fi

            # Check if all components exist
            if [ -f "$DB_BACKUP" ] && [ -f "$FILES_BACKUP" ] && [ -f "$CONFIG_BACKUP" ] && [ -f "$MANIFEST" ]; then
                log_success "✅ Complete backup set found for timestamp: $LATEST_TIMESTAMP"
            else
                log_warning "⚠️  Incomplete backup set for timestamp: $LATEST_TIMESTAMP"
            fi
        else
            log_warning "⚠️  No database backups found"
        fi
    else
        log_error "❌ Backup directory structure is incomplete"
    fi

    echo ""
}

# Function: Show backup statistics
show_backup_stats() {
    log_header "📈 BACKUP STATISTICS"

    # Count backups by type
    DB_COUNT=$(find "$BACKUP_PATH/database" -name "*.backup" 2>/dev/null | wc -l)
    FILES_COUNT=$(find "$BACKUP_PATH/files" -name "*.tar.gz" 2>/dev/null | wc -l)
    CONFIG_COUNT=$(find "$BACKUP_PATH/config" -name "*.tar.gz" 2>/dev/null | wc -l)
    MANIFEST_COUNT=$(find "$BACKUP_PATH" -name "*.manifest" 2>/dev/null | wc -l)

    echo "📊 Backup Counts:"
    echo "  Database: $DB_COUNT"
    echo "  Files: $FILES_COUNT"
    echo "  Config: $CONFIG_COUNT"
    echo "  Manifests: $MANIFEST_COUNT"
    echo ""

    # Calculate total backup size
    TOTAL_SIZE=$(du -sh "$BACKUP_PATH" | cut -f1)
    echo "💾 Total Backup Size: $TOTAL_SIZE"

    # Show directory sizes
    echo "📁 Directory Sizes:"
    if [ -d "$BACKUP_PATH/database" ]; then
        DB_SIZE=$(du -sh "$BACKUP_PATH/database" | cut -f1)
        echo "  Database: $DB_SIZE"
    fi

    if [ -d "$BACKUP_PATH/files" ]; then
        FILES_SIZE=$(du -sh "$BACKUP_PATH/files" | cut -f1)
        echo "  Files: $FILES_SIZE"
    fi

    if [ -d "$BACKUP_PATH/config" ]; then
        CONFIG_SIZE=$(du -sh "$BACKUP_PATH/config" | cut -f1)
        echo "  Config: $CONFIG_SIZE"
    fi

    echo ""
}

# Function: Show next backup schedule
show_next_backup() {
    log_header "⏰ NEXT BACKUP SCHEDULE"

    echo "🔄 Automated Backup Schedule:"
    echo "  Frequency: Daily at 2:00 AM"
    echo "  Next run: Tomorrow at 2:00 AM"
    echo "  Retention: $RETENTION_DAYS days"
    echo ""

    echo "📅 Manual Backup Options:"
    echo "  GitHub Actions: Actions > System Backup > Run workflow"
    echo "  Server Script: ./scripts/backup-manual.sh"
    echo ""
}

# Function: Show recommendations
show_recommendations() {
    log_header "💡 RECOMMENDATIONS"

    # Check if backups are recent
    LATEST_BACKUP=$(find "$BACKUP_PATH" -name "*.backup" -o -name "*.tar.gz" -o -name "*.manifest" 2>/dev/null | xargs ls -t 2>/dev/null | head -1)

    if [ -n "$LATEST_BACKUP" ]; then
        BACKUP_AGE_HOURS=$(( $(date +%s) - $(stat -c %Y "$LATEST_BACKUP") ))
        BACKUP_AGE_HOURS=$((BACKUP_AGE_HOURS / 3600))

        if [ "$BACKUP_AGE_HOURS" -gt 48 ]; then
            log_warning "⚠️  Latest backup is $BACKUP_AGE_HOURS hours old"
            echo "  Recommendation: Run manual backup soon"
        else
            log_success "✅ Backups are recent ($BACKUP_AGE_HOURS hours old)"
        fi
    fi

    # Check disk space
    DISK_USAGE=$(df "$BACKUP_PATH" | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$DISK_USAGE" -gt 80 ]; then
        log_warning "⚠️  Disk usage is high ($DISK_USAGE%)"
        echo "  Recommendation: Consider reducing retention or increasing disk space"
    fi

    # Check backup completeness
    if [ -d "$BACKUP_PATH/database" ] && [ -d "$BACKUP_PATH/files" ] && [ -d "$BACKUP_PATH/config" ]; then
        DB_COUNT=$(find "$BACKUP_PATH/database" -name "*.backup" 2>/dev/null | wc -l)
        FILES_COUNT=$(find "$BACKUP_PATH/files" -name "*.tar.gz" 2>/dev/null | wc -l)
        CONFIG_COUNT=$(find "$BACKUP_PATH/config" -name "*.tar.gz" 2>/dev/null | wc -l)

        if [ "$DB_COUNT" -eq 0 ] || [ "$FILES_COUNT" -eq 0 ] || [ "$CONFIG_COUNT" -eq 0 ]; then
            log_warning "⚠️  Some backup types are missing"
            echo "  Recommendation: Run full backup to ensure completeness"
        fi
    fi

    echo ""
}

# Main function
main() {
    echo ""
    log_header "🗄️ SHOPSIFU BACKUP STATUS REPORT"
    log_header "================================="
    echo ""

    # Run all checks
    check_disk_usage
    list_backups_by_type
    check_backup_age
    check_backup_integrity
    show_backup_stats
    show_next_backup
    show_recommendations

    log_success "✅ Backup status check completed!"
    echo ""
}

# Run main function
main "$@"
