# 🚀 Quick Start Guide

Hướng dẫn nhanh để setup ShopSifu Server từ đầu hoặc migrate sang server mới.

## ⚡ Setup Server Mới (Tự động)

```bash
# Clone repository và vào thư mục
cd server-shopsifu

# Chạy script setup tự động
./scripts/setup.sh
```

Script sẽ tự động:
- ✅ Kiểm tra và cài đặt Docker & Docker Compose
- ✅ Cài đặt npm dependencies
- ✅ Khởi động core services (PostgreSQL, Redis, Elasticsearch)
- ✅ Setup database (migrations, seed)
- ✅ Build application

## 📋 Setup Server Mới (Thủ công)

### 1. Cài đặt Docker
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
# Logout và login lại
```

### 2. Clone và cài đặt
```bash
cd server-shopsifu
npm install
cp .env.example .env
nano .env  # Cập nhật các giá trị cần thiết
```

### 3. Khởi động services
```bash
# Core services
docker-compose -f docker-compose.core.yml up -d

# Đợi 30-60 giây để services khởi động
sleep 30

# Setup database
npm run generate
npm run migrate
npm run seed  # (tùy chọn)

# Monitoring services (tùy chọn)
docker-compose -f docker-compose.monitoring.yml up -d
```

### 4. Build và chạy ứng dụng
```bash
npm run build
npm start  # hoặc pm2 start ecosystem.config.js
```

## 🔄 Migration sang Server Mới

### Trên Server Cũ: Backup

```bash
# Chạy script backup
./scripts/migrate.sh
# Chọn option 1: Backup data

# Hoặc backup thủ công:
docker exec shopsifu_postgres pg_dump -U shopsifu shopsifu > backup.sql
docker cp shopsifu_redis:/data/dump.rdb ./backup.rdb
```

### Trên Server Mới: Restore

```bash
# 1. Setup server mới (theo hướng dẫn ở trên)
./scripts/setup.sh

# 2. Copy backup files vào thư mục backups/
scp backup.sql user@new-server:/path/to/server-shopsifu/backups/

# 3. Restore
./scripts/migrate.sh
# Chọn option 2: Restore data
# Nhập tên file backup khi được hỏi
```

## 🐳 Docker Commands Nhanh

```bash
# Khởi động tất cả services
docker-compose up -d

# Chỉ core services
docker-compose -f docker-compose.core.yml up -d

# Chỉ monitoring services
docker-compose -f docker-compose.monitoring.yml up -d

# Dừng services
docker-compose down

# Xem logs
docker-compose logs -f [service_name]

# Xem status
docker-compose ps

# Restart service
docker-compose restart [service_name]
```

## 🔍 Kiểm tra Services

```bash
# PostgreSQL
docker exec shopsifu_postgres pg_isready -U shopsifu

# Redis
docker exec shopsifu_redis redis-cli -a Shopsifu2025 PING

# Elasticsearch
curl http://localhost:9200/_cluster/health

# Application
curl http://localhost:3000/health
```

## 📚 Tài liệu chi tiết

Xem [README.md](README.md) để biết thêm chi tiết về:
- Cấu hình Nginx
- SSL certificates
- Troubleshooting
- Security best practices

## ⚠️ Lưu ý quan trọng

1. **Đổi mật khẩu mặc định** trong `.env` và `docker-compose.core.yml`
2. **Không commit file `.env`** vào git
3. **Backup thường xuyên** database và volumes
4. **Kiểm tra logs** nếu có vấn đề: `docker-compose logs -f`

## 🆘 Cần giúp đỡ?

Xem phần **Troubleshooting** trong [README.md](README.md)

