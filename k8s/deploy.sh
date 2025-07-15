#!/bin/bash
# k8s/deploy.sh
# Simple deployment script

echo "🚀 Deploying NestJS Starter..."

# Deploy everything
kubectl apply -f deployment.yaml

echo "✅ Deployed! Checking status..."

# Wait a bit and show status
sleep 5
kubectl get pods -n shopsifu

echo ""
echo "📋 To access your app:"
echo "kubectl port-forward service/shopsifu-service 3001:80 -n shopsifu"
echo ""
echo "Then visit: http://localhost:3001"
