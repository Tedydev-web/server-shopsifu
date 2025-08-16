#!/bin/bash

# ==============================================
# DOCKER CLEANUP SCRIPT FOR SHOPSIFU
# ==============================================

echo "🧹 Starting Docker cleanup for ShopSifu..."

# ==============================================
# STOP AND REMOVE STACKS
# ==============================================
echo "📦 Stopping Docker stacks..."

# List all stacks
STACKS=$(docker stack ls --format "{{.Name}}")

if [ ! -z "$STACKS" ]; then
    echo "Found stacks: $STACKS"
    
    # Remove each stack
    for stack in $STACKS; do
        echo "Removing stack: $stack"
        docker stack rm $stack
        sleep 10
    done
    
    echo "Waiting for all stacks to be removed..."
    sleep 30
else
    echo "No stacks found."
fi

# ==============================================
# CLEANUP DOCKER RESOURCES
# ==============================================
echo "🗑️ Cleaning up Docker resources..."

# Remove stopped containers
echo "Removing stopped containers..."
docker container prune -f

# Remove unused networks
echo "Removing unused networks..."
docker network prune -f

# Remove unused volumes
echo "Removing unused volumes..."
docker volume prune -f

# Remove unused images
echo "Removing unused images..."
docker image prune -f

# Remove build cache
echo "Removing build cache..."
docker builder prune -f

# Full system cleanup
echo "Performing full system cleanup..."
docker system prune -f

# ==============================================
# VERIFY CLEANUP
# ==============================================
echo "✅ Cleanup completed!"
echo ""
echo "📊 Current Docker status:"
echo "Containers: $(docker ps -q | wc -l) running, $(docker ps -aq | wc -l) total"
echo "Images: $(docker images -q | wc -l)"
echo "Volumes: $(docker volume ls -q | wc -l)"
echo "Networks: $(docker network ls -q | wc -l)"
echo "Stacks: $(docker stack ls -q | wc -l)"

echo ""
echo "🎯 Ready for fresh deployment!"
