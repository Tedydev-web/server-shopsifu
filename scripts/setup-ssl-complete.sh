#!/bin/bash

# Script hoàn chỉnh setup SSL cho tất cả domains với auto-renewal
# Chạy với: bash scripts/setup-ssl-complete.sh

set -e

echo "🔐 Setup SSL hoàn chỉnh cho tất cả domains..."

# 1. Cài đặt Certbot nếu chưa có
echo "📦 Kiểm tra và cài đặt Certbot..."
if ! command -v certbot &> /dev/null; then
    echo "🔧 Cài đặt Certbot..."
    sudo apt update
    sudo apt install -y certbot
fi

# 2. Tạo cấu trúc thư mục SSL
echo "📁 Tạo cấu trúc thư mục SSL..."
mkdir -p nginx/ssl/api
mkdir -p nginx/ssl/grafana
mkdir -p nginx/ssl/prometheus

# 3. Tạo certificates cho tất cả domains
echo "🔐 Tạo certificates cho tất cả domains..."

# API (nếu chưa có)
if [ ! -f "/etc/letsencrypt/live/api.shopsifu.live/fullchain.pem" ]; then
    echo "🔐 Tạo certificate cho API..."
    sudo certbot certonly --standalone \
        -d api.shopsifu.live \
        -d www.api.shopsifu.live \
        --non-interactive \
        --agree-tos \
        --email admin@shopsifu.live
fi

# Grafana
echo "🔐 Tạo certificate cho Grafana..."
sudo certbot certonly --standalone \
    -d grafana.shopsifu.live \
    --non-interactive \
    --agree-tos \
    --email admin@shopsifu.live

# Prometheus
echo "🔐 Tạo certificate cho Prometheus..."
sudo certbot certonly --standalone \
    -d prometheus.shopsifu.live \
    --non-interactive \
    --agree-tos \
    --email admin@shopsifu.live

# 4. Copy certificates
echo "📋 Copy certificates..."

# API
sudo cp /etc/letsencrypt/live/api.shopsifu.live/fullchain.pem nginx/ssl/api/
sudo cp /etc/letsencrypt/live/api.shopsifu.live/privkey.pem nginx/ssl/api/

# Grafana
sudo cp /etc/letsencrypt/live/grafana.shopsifu.live/fullchain.pem nginx/ssl/grafana/
sudo cp /etc/letsencrypt/live/grafana.shopsifu.live/privkey.pem nginx/ssl/grafana/

# Prometheus
sudo cp /etc/letsencrypt/live/prometheus.shopsifu.live/fullchain.pem nginx/ssl/prometheus/
sudo cp /etc/letsencrypt/live/prometheus.shopsifu.live/privkey.pem nginx/ssl/prometheus/

# 5. Copy SSL options
echo "⚙️ Copy SSL options..."
sudo cp /etc/letsencrypt/options-ssl-nginx.conf nginx/ssl/
sudo cp /etc/letsencrypt/ssl-dhparams.pem nginx/ssl/

# 6. Set permissions
echo "🔒 Set permissions..."
sudo chown -R $USER:$USER nginx/ssl/
find nginx/ssl/ -name "*.pem" -exec chmod 600 {} \;
find nginx/ssl/ -name "*.conf" -exec chmod 644 {} \;

# 7. Tạo script auto-renewal
echo "📝 Tạo script auto-renewal..."
cat > scripts/renew-ssl.sh << 'EOF'
#!/bin/bash

# Script auto-renewal SSL certificates
# Chạy với: bash scripts/renew-ssl.sh

set -e

echo "🔄 Auto-renewal SSL certificates..."

# 1. Renew tất cả certificates
echo "🔐 Renew certificates..."
sudo certbot renew --quiet

# 2. Copy certificates mới
echo "📋 Copy certificates mới..."

# API
sudo cp /etc/letsencrypt/live/api.shopsifu.live/fullchain.pem nginx/ssl/api/
sudo cp /etc/letsencrypt/live/api.shopsifu.live/privkey.pem nginx/ssl/api/

# Grafana
sudo cp /etc/letsencrypt/live/grafana.shopsifu.live/fullchain.pem nginx/ssl/grafana/
sudo cp /etc/letsencrypt/live/grafana.shopsifu.live/privkey.pem nginx/ssl/grafana/

# Prometheus
sudo cp /etc/letsencrypt/live/prometheus.shopsifu.live/fullchain.pem nginx/ssl/prometheus/
sudo cp /etc/letsencrypt/live/prometheus.shopsifu.live/privkey.pem nginx/ssl/prometheus/

# 3. Set permissions
echo "🔒 Set permissions..."
sudo chown -R $USER:$USER nginx/ssl/
find nginx/ssl/ -name "*.pem" -exec chmod 600 {} \;

# 4. Restart nginx
echo "🔄 Restart nginx..."
docker compose restart nginx

# 5. Test certificates
echo "🧪 Test certificates..."
sleep 5
echo "API:"
curl -I https://api.shopsifu.live/health || echo "⚠️  API chưa sẵn sàng"
echo "Grafana:"
curl -I -u admin:Shopsifu2025@@ https://grafana.shopsifu.live || echo "⚠️  Grafana chưa sẵn sàng"
echo "Prometheus:"
curl -I -u admin:Shopsifu2025@@ https://prometheus.shopsifu.live || echo "⚠️  Prometheus chưa sẵn sàng"

echo "✅ Auto-renewal hoàn tất!"
EOF

chmod +x scripts/renew-ssl.sh

# 8. Setup crontab cho auto-renewal (2 lần/tháng)
echo "📅 Setup auto-renewal..."
if ! crontab -l 2>/dev/null | grep -q "renew-ssl.sh"; then
    (crontab -l 2>/dev/null; echo "0 12 1,15 * * /usr/bin/certbot renew --quiet && bash $(pwd)/scripts/renew-ssl.sh") | crontab -
    echo "✅ Đã thêm auto-renewal vào crontab (ngày 1 và 15 hàng tháng)"
else
    echo "ℹ️  Auto-renewal đã được setup trước đó"
fi

# 9. Test certificates
echo "🧪 Test certificates..."
echo "API:"
openssl x509 -in nginx/ssl/api/fullchain.pem -text -noout | grep "Subject:"
echo "Grafana:"
openssl x509 -in nginx/ssl/grafana/fullchain.pem -text -noout | grep "Subject:"
echo "Prometheus:"
openssl x509 -in nginx/ssl/prometheus/fullchain.pem -text -noout | grep "Subject:"

# 10. Deploy Docker stack
echo "🐳 Deploy Docker stack..."
docker compose pull
docker compose up -d nginx server grafana prometheus

# 11. Test kết nối
echo "🧪 Test kết nối..."
sleep 10
echo "API:"
curl -I https://api.shopsifu.live/health || echo "⚠️  API chưa sẵn sàng"
echo "Grafana:"
curl -I -u admin:Shopsifu2025@@ https://grafana.shopsifu.live || echo "⚠️  Grafana chưa sẵn sàng"
echo "Prometheus:"
curl -I -u admin:Shopsifu2025@@ https://prometheus.shopsifu.live || echo "⚠️  Prometheus chưa sẵn sàng"

echo "✅ Setup SSL hoàn tất!"
echo ""
echo "📋 Cấu trúc SSL:"
echo "nginx/ssl/"
echo "├── api/"
echo "│   ├── fullchain.pem"
echo "│   └── privkey.pem"
echo "├── grafana/"
echo "│   ├── fullchain.pem"
echo "│   └── privkey.pem"
echo "├── prometheus/"
echo "│   ├── fullchain.pem"
echo "│   └── privkey.pem"
echo "├── options-ssl-nginx.conf"
echo "└── ssl-dhparams.pem"
echo ""
echo "🔗 Endpoints:"
echo "- API: https://api.shopsifu.live"
echo "- Grafana: https://grafana.shopsifu.live (admin/Shopsifu2025@@)"
echo "- Prometheus: https://prometheus.shopsifu.live (admin/Shopsifu2025@@)"
echo ""
echo "🔄 Auto-renewal:"
echo "- Đã setup crontab để tự động renew ngày 1 và 15 hàng tháng lúc 12:00"
echo "- Script: scripts/renew-ssl.sh"
echo "- Logs: /var/log/letsencrypt/letsencrypt.log"
echo ""
echo "📋 Các lệnh hữu ích:"
echo "- Kiểm tra crontab: crontab -l"
echo "- Manual renew: bash scripts/renew-ssl.sh"
echo "- Xem logs: tail -f /var/log/letsencrypt/letsencrypt.log"
echo "- Test certificates: openssl s_client -connect domain:443 -servername domain"
