#!/bin/bash

# Script kiểm tra trạng thái SSL certificates
# Chạy với: bash scripts/check-ssl-status.sh

set -e

echo "🔍 Kiểm tra trạng thái SSL certificates..."

# 1. Kiểm tra certificates tồn tại
echo "📋 Kiểm tra certificates..."
for domain in api grafana prometheus; do
    if [ -f "nginx/ssl/$domain/fullchain.pem" ] && [ -f "nginx/ssl/$domain/privkey.pem" ]; then
        echo "✅ $domain.shopsifu.live: OK"
    else
        echo "❌ $domain.shopsifu.live: Missing certificates"
    fi
done

# 2. Kiểm tra thời hạn certificates
echo ""
echo "📅 Kiểm tra thời hạn certificates..."
for domain in api grafana prometheus; do
    if [ -f "nginx/ssl/$domain/fullchain.pem" ]; then
        echo "$domain.shopsifu.live:"
        openssl x509 -in nginx/ssl/$domain/fullchain.pem -text -noout | grep -E "(Subject:|Not Before|Not After)"
        echo ""
    fi
done

# 3. Kiểm tra Let's Encrypt certificates
echo "🔐 Kiểm tra Let's Encrypt certificates..."
for domain in api grafana prometheus; do
    if [ -d "/etc/letsencrypt/live/$domain.shopsifu.live" ]; then
        echo "✅ $domain.shopsifu.live: Let's Encrypt OK"
    else
        echo "❌ $domain.shopsifu.live: Let's Encrypt missing"
    fi
done

# 4. Kiểm tra auto-renewal
echo ""
echo "🔄 Kiểm tra auto-renewal..."
if crontab -l 2>/dev/null | grep -q "renew-ssl.sh"; then
    echo "✅ Auto-renewal: Đã setup"
    crontab -l | grep "renew-ssl.sh"
else
    echo "❌ Auto-renewal: Chưa setup"
fi

# 5. Kiểm tra Docker services
echo ""
echo "🐳 Kiểm tra Docker services..."
if docker compose ps nginx | grep -q "Up"; then
    echo "✅ Nginx: Running"
else
    echo "❌ Nginx: Not running"
fi

# 6. Test kết nối HTTPS
echo ""
echo "🌐 Test kết nối HTTPS..."
for domain in api grafana prometheus; do
    echo "$domain.shopsifu.live:"
    if curl -s -I "https://$domain.shopsifu.live" > /dev/null 2>&1; then
        echo "  ✅ HTTPS: OK"
    else
        echo "  ❌ HTTPS: Failed"
    fi
done

# 7. Kiểm tra SSL certificate details
echo ""
echo "🔍 Chi tiết SSL certificates..."
for domain in api grafana prometheus; do
    if [ -f "nginx/ssl/$domain/fullchain.pem" ]; then
        echo "$domain.shopsifu.live:"
        echo "  Issuer: $(openssl x509 -in nginx/ssl/$domain/fullchain.pem -text -noout | grep "Issuer:" | head -1)"
        echo "  Valid: $(openssl x509 -in nginx/ssl/$domain/fullchain.pem -text -noout | grep "Not After" | head -1)"
        echo ""
    fi
done

# 8. Kiểm tra permissions
echo "🔒 Kiểm tra permissions..."
for domain in api grafana prometheus; do
    if [ -f "nginx/ssl/$domain/privkey.pem" ]; then
        perms=$(stat -c %a nginx/ssl/$domain/privkey.pem)
        if [ "$perms" = "600" ]; then
            echo "✅ $domain: Permissions OK ($perms)"
        else
            echo "❌ $domain: Wrong permissions ($perms, should be 600)"
        fi
    fi
done

echo ""
echo "📋 Tóm tắt:"
echo "- Certificates: $(ls nginx/ssl/*/fullchain.pem 2>/dev/null | wc -l)/3 domains"
echo "- Auto-renewal: $(if crontab -l 2>/dev/null | grep -q "renew-ssl.sh"; then echo "OK"; else echo "Missing"; fi)"
echo "- Nginx: $(if docker compose ps nginx | grep -q "Up"; then echo "Running"; else echo "Stopped"; fi)"
echo "- HTTPS: $(for domain in api grafana prometheus; do if curl -s -I "https://$domain.shopsifu.live" > /dev/null 2>&1; then echo -n "✅"; else echo -n "❌"; fi; done)"
