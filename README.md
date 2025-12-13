# ShopSifu Server

Backend API server cho hệ thống e-commerce ShopSifu, được xây dựng với NestJS, PostgreSQL, Redis, và Elasticsearch.

## 📋 Yêu cầu hệ thống

- **OS**: Ubuntu 20.04+ / Debian 11+ / CentOS 8+
- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **Node.js**: 18.x hoặc 20.x
- **npm**: 9.x+
- **PM2**: (tùy chọn, để quản lý process)

## 🚀 Hướng dẫn Setup từ đầu

### Bước 1: Cài đặt Docker & Docker Compose

```bash
# Cài đặt Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Cài đặt Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Logout và login lại để áp dụng group docker
exit
# (login lại)

# Kiểm tra cài đặt
docker --version
docker-compose --version
```

### Bước 2: Clone repository và cài đặt dependencies

```bash
# Clone repository (hoặc upload code lên server)
cd /path/to/your/workspace
git clone <repository-url> server-shopsifu
cd server-shopsifu

# Cài đặt Node.js dependencies
npm install
```

### Bước 3: Cấu hình Environment Variables

```bash
# Copy file .env mẫu (nếu có) hoặc tạo mới
cp .env.example .env  # hoặc tạo file .env mới

# Chỉnh sửa file .env với các thông tin của bạn
nano .env
```

**Quan trọng**: Đảm bảo các biến sau trong `.env` đúng với Docker setup:

```env
# Database - kết nối tới PostgreSQL container
DATABASE_URL=postgresql://shopsifu:Shopsifu2025@localhost:5432/shopsifu?schema=public&connection_limit=5

# Redis - kết nối tới Redis container
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=Shopsifu2025
REDIS_URL=redis://:Shopsifu2025@localhost:6379

# Elasticsearch - kết nối tới Elasticsearch container
ELASTICSEARCH_NODE=http://localhost:9200
```

### Bước 4: Khởi động Core Services (PostgreSQL, Redis, Elasticsearch)

```bash
# Khởi động core services
docker-compose -f docker-compose.core.yml up -d

# Kiểm tra status
docker-compose -f docker-compose.core.yml ps

# Xem logs (nếu cần)
docker-compose -f docker-compose.core.yml logs -f
```

**Đợi khoảng 30-60 giây** để các services khởi động hoàn toàn, đặc biệt là PostgreSQL và Elasticsearch.

### Bước 5: Setup Database

```bash
# Generate Prisma Client
npm run generate

# Chạy database migrations
npm run migrate

# Seed dữ liệu ban đầu
npm run seed
```

### Bước 6: Khởi động Monitoring Services (tùy chọn)

```bash
# Khởi động monitoring services (Prometheus, Grafana, Kibana, etc.)
docker-compose -f docker-compose.monitoring.yml up -d

# Hoặc khởi động tất cả (core + monitoring)
docker-compose up -d
```

### Bước 7: Khởi động Application

```bash
# Build ứng dụng
npm run build

# Khởi động với PM2 (recommended cho production)
pm2 start ecosystem.config.js

# Hoặc khởi động trực tiếp
npm start

# Hoặc development mode
npm run dev
```

### Bước 8: Cấu hình Nginx (Production)

Xem hướng dẫn chi tiết trong [docs/nginx-setup.md](docs/nginx-setup.md) hoặc:

```bash
# Copy Nginx config
sudo cp nginx-config/api.shopsifu.live.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/api.shopsifu.live.conf /etc/nginx/sites-enabled/

# Test và reload Nginx
sudo nginx -t
sudo systemctl reload nginx
```

### Bước 9: Cấu hình SSL với Let's Encrypt

```bash
# Cài đặt Certbot
sudo apt update
sudo apt install certbot python3-certbot-nginx

# Lấy SSL certificate
sudo certbot --nginx -d api.shopsifu.live
sudo certbot --nginx -d grafana.shopsifu.live
sudo certbot --nginx -d prometheus.shopsifu.live
sudo certbot --nginx -d kibana.shopsifu.live
sudo certbot --nginx -d elasticsearch.shopsifu.live

# Auto-renewal (đã tự động cấu hình)
sudo certbot renew --dry-run
```

## 🔄 Migration sang Server mới

### Script tự động migration

Chúng tôi cung cấp script để dễ dàng migrate:

```bash
# Sử dụng script migration
./scripts/migrate.sh

# Hoặc chạy các bước thủ công dưới đây
```

### Migration thủ công

#### 1. Trên server cũ: Backup dữ liệu

```bash
# Backup PostgreSQL
docker exec shopsifu_postgres pg_dump -U shopsifu shopsifu > backup_postgres_$(date +%Y%m%d_%H%M%S).sql

# Backup Redis (nếu cần)
docker exec shopsifu_redis redis-cli --rdb /data/dump.rdb -a Shopsifu2025
docker cp shopsifu_redis:/data/dump.rdb ./backup_redis_$(date +%Y%m%d_%H%M%S).rdb

# Backup Elasticsearch (nếu cần)
# Xem: https://www.elastic.co/guide/en/elasticsearch/reference/current/snapshots-register-repository.html

# Backup volumes (nếu muốn backup toàn bộ)
docker run --rm -v shopsifu_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_data_$(date +%Y%m%d_%H%M%S).tar.gz /data
docker run --rm -v shopsifu_redis_data:/data -v $(pwd):/backup alpine tar czf /backup/redis_data_$(date +%Y%m%d_%H%M%S).tar.gz /data
docker run --rm -v shopsifu_elasticsearch_data:/data -v $(pwd):/backup alpine tar czf /backup/elasticsearch_data_$(date +%Y%m%d_%H%M%S).tar.gz /data
```

#### 2. Trên server mới: Setup từ đầu

Làm theo **Bước 1-6** ở trên.

#### 3. Trên server mới: Restore dữ liệu

```bash
# Restore PostgreSQL
cat backup_postgres_YYYYMMDD_HHMMSS.sql | docker exec -i shopsifu_postgres psql -U shopsifu -d shopsifu

# Restore Redis (nếu có backup)
docker cp backup_redis_YYYYMMDD_HHMMSS.rdb shopsifu_redis:/data/dump.rdb
docker restart shopsifu_redis

# Restore volumes (nếu backup volumes)
docker run --rm -v shopsifu_postgres_data:/data -v $(pwd):/backup alpine sh -c "cd /data && tar xzf /backup/postgres_data_YYYYMMDD_HHMMSS.tar.gz"
docker run --rm -v shopsifu_redis_data:/data -v $(pwd):/backup alpine sh -c "cd /data && tar xzf /backup/redis_data_YYYYMMDD_HHMMSS.tar.gz"
docker run --rm -v shopsifu_elasticsearch_data:/data -v $(pwd):/backup alpine sh -c "cd /data && tar xzf /backup/elasticsearch_data_YYYYMMDD_HHMMSS.tar.gz"
```

#### 4. Cập nhật DNS và Nginx

- Cập nhật DNS records trên Cloudflare hoặc DNS provider
- Cấu hình Nginx như Bước 8
- Lấy SSL certificates như Bước 9

## 📦 Docker Commands

### Quản lý Core Services

```bash
# Khởi động
docker-compose -f docker-compose.core.yml up -d

# Dừng
docker-compose -f docker-compose.core.yml down

# Restart
docker-compose -f docker-compose.core.yml restart

# Xem logs
docker-compose -f docker-compose.core.yml logs -f [service_name]

# Xem status
docker-compose -f docker-compose.core.yml ps

# Truy cập vào container
docker exec -it shopsifu_postgres psql -U shopsifu -d shopsifu
docker exec -it shopsifu_redis redis-cli -a Shopsifu2025
docker exec -it shopsifu_elasticsearch curl http://localhost:9200
```

### Quản lý Monitoring Services

```bash
# Khởi động
docker-compose -f docker-compose.monitoring.yml up -d

# Dừng
docker-compose -f docker-compose.monitoring.yml down

# Restart
docker-compose -f docker-compose.monitoring.yml restart
```

### Quản lý tất cả Services

```bash
# Khởi động tất cả
docker-compose up -d

# Dừng tất cả
docker-compose down

# Restart tất cả
docker-compose restart

# Xem logs tất cả
docker-compose logs -f

# Xem status tất cả
docker-compose ps
```

### Backup & Restore Volumes

```bash
# Backup volume
docker run --rm -v shopsifu_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_backup.tar.gz /data

# Restore volume (CẨN THẬN: sẽ ghi đè dữ liệu hiện tại!)
docker run --rm -v shopsifu_postgres_data:/data -v $(pwd):/backup alpine sh -c "cd /data && tar xzf /backup/postgres_backup.tar.gz --strip 1"
```

## 🔧 Troubleshooting

### PostgreSQL không kết nối được

```bash
# Kiểm tra container đang chạy
docker ps | grep postgres

# Kiểm tra logs
docker logs shopsifu_postgres

# Kiểm tra kết nối từ host
docker exec -it shopsifu_postgres psql -U shopsifu -d shopsifu -c "SELECT version();"
```

### Redis không kết nối được

```bash
# Kiểm tra container
docker ps | grep redis

# Test kết nối
docker exec -it shopsifu_redis redis-cli -a Shopsifu2025 PING
```

### Elasticsearch không khởi động

```bash
# Kiểm tra logs
docker logs shopsifu_elasticsearch

# Kiểm tra memory (Elasticsearch cần đủ RAM)
free -h

# Kiểm tra health
curl http://localhost:9200/_cluster/health
```

### "Too many database connections"

```bash
# Đóng idle connections
docker exec -it shopsifu_postgres psql -U shopsifu -d shopsifu -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'shopsifu' AND state = 'idle' AND pid != pg_backend_pid();"

# Hoặc restart PostgreSQL container
docker restart shopsifu_postgres
```

### Port đã được sử dụng

```bash
# Kiểm tra port nào đang được sử dụng
sudo netstat -tulpn | grep :5432
sudo netstat -tulpn | grep :6379
sudo netstat -tulpn | grep :9200

# Dừng service đang chiếm port hoặc đổi port trong docker-compose.yml
```

## 📊 Monitoring & Health Checks

### Health Endpoints

- Application: `http://localhost:3000/health`
- PostgreSQL: `docker exec shopsifu_postgres pg_isready -U shopsifu`
- Redis: `docker exec shopsifu_redis redis-cli -a Shopsifu2025 PING`
- Elasticsearch: `curl http://localhost:9200/_cluster/health`

### Monitoring Dashboards

- Grafana: `http://localhost:3001` (admin/Shopsifu2025)
- Prometheus: `http://localhost:9090`
- Kibana: `http://localhost:5601`
- Elasticsearch: `http://localhost:9200`

## 📝 Environment Variables

Xem file `.env.example` (nếu có) hoặc file `.env` để biết các biến môi trường cần thiết.

**Lưu ý quan trọng**:
- Không commit file `.env` vào git
- Thay đổi các password mặc định trong production
- Sử dụng secrets management (AWS Secrets Manager, HashiCorp Vault, etc.) cho production

## 🎯 Quick Start (Tóm tắt)

```bash
# 1. Setup Docker
curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh

# 2. Clone & Install
git clone <repo> && cd server-shopsifu && npm install

# 3. Configure
cp .env.example .env && nano .env

# 4. Start Core Services
docker-compose -f docker-compose.core.yml up -d

# 5. Setup Database
npm run generate && npm run migrate && npm run seed

# 6. Start App
npm run build && npm start
```

## 📚 Cấu trúc Docker Compose

- `docker-compose.yml`: File chính, include cả core và monitoring
- `docker-compose.core.yml`: Core services (PostgreSQL, Redis, Elasticsearch)
- `docker-compose.monitoring.yml`: Monitoring services (Prometheus, Grafana, Kibana, Exporters)

## 🔐 Security Notes

1. **Đổi mật khẩu mặc định** trong `.env` và `docker-compose.yml`
2. **Không expose** services ra ngoài internet trừ khi cần (dùng Nginx reverse proxy)
3. **Sử dụng SSL/TLS** cho tất cả connections
4. **Regular backups** cho database
5. **Update Docker images** thường xuyên để có security patches

## 📞 Support

Nếu gặp vấn đề, vui lòng:
1. Kiểm tra logs: `docker-compose logs -f [service_name]`
2. Kiểm tra health checks
3. Xem phần Troubleshooting ở trên
4. Tạo issue trên GitHub repository

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**TedyDev**

- 🌐 [GitHub](https://github.com/Tedydev-web)
- 💼 [LinkedIn](https://www.linkedin.com/in/hieudat-tedydev)
- 📷 [Facebook](https://www.facebook.com/tedydevweb)

---

**Happy Coding! 🎉**
