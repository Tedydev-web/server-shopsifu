# 🚀 ShopSifu Backend Server

Backend server cho ứng dụng e-commerce ShopSifu, được xây dựng với NestJS và tối ưu hóa cho Docker Swarm.

## 🏗️ **Kiến trúc hệ thống**

- **Framework**: NestJS (Node.js)
- **Database**: PostgreSQL 16 với PgBouncer connection pooling
- **Cache**: Redis 7 với persistence
- **Search**: Elasticsearch 8.13.4
- **Monitoring**: Prometheus + Grafana
- **Logging**: Kibana
- **Deployment**: Docker Swarm

## 🚀 **Khởi chạy với Docker Swarm**

### 1. **Chuẩn bị môi trường**

```bash
# Kiểm tra Docker Swarm
docker info | grep -i swarm

# Khởi tạo Swarm (nếu chưa có)
docker swarm init

# Tạo các thư mục cần thiết
mkdir -p logs certs upload monitoring/prometheus monitoring/grafana
```

### 2. **Cấu hình môi trường**

```bash
# Copy file môi trường
cp .env.example .env.docker

# Chỉnh sửa các biến môi trường cần thiết
nano .env.docker
```

### 3. **Khởi chạy stack**

```bash
# Deploy stack
docker stack deploy -c docker-compose.swarm.yml shopsifu

# Kiểm tra trạng thái
docker service ls

# Xem logs
docker service logs shopsifu_server
```

### 4. **Kiểm tra hoạt động**

```bash
# Health check
curl http://localhost:3000/health

# Kiểm tra Elasticsearch
curl http://localhost:9200

# Kiểm tra Prometheus
curl http://localhost:9090/-/healthy

# Kiểm tra Grafana
curl http://localhost:3001/api/health
```

## 🔧 **Quản lý Docker Swarm**

### **Xem trạng thái services**
```bash
docker service ls
docker service ps shopsifu_server
```

### **Scale services**
```bash
# Scale server lên 5 replicas
docker service scale shopsifu_server=5

# Scale xuống 2 replicas
docker service scale shopsifu_server=2
```

### **Update service**
```bash
# Update image
docker service update --image server-shopsifu:new-version shopsifu_server

# Update environment variables
docker service update --env-add NEW_VAR=value shopsifu_server
```

### **Rollback service**
```bash
docker service rollback shopsifu_server
```

### **Dừng và xóa stack**
```bash
# Dừng stack
docker stack rm shopsifu

# Xóa volumes (cẩn thận!)
docker volume prune -f
```

## 📊 **Monitoring & Logging**

### **Prometheus**
- **Port**: 9090
- **Metrics**: Application, PostgreSQL, Redis, Elasticsearch
- **Retention**: 30 ngày

### **Grafana**
- **Port**: 3001
- **Admin**: admin/Shopsifu2025
- **Dashboards**: Pre-configured cho ShopSifu

### **Kibana**
- **Port**: 5601
- **Features**: Log analysis, search, visualization

## 🗄️ **Database & Cache**

### **PostgreSQL**
- **Port**: 5432
- **Connection Pool**: PgBouncer (port 6432)
- **Max Connections**: 2000
- **Optimized**: 30 cores, 25GB RAM

### **Redis**
- **Port**: 6379
- **Memory**: 20GB
- **Persistence**: AOF + RDB
- **Policy**: noeviction

### **Elasticsearch**
- **Port**: 9200
- **Memory**: 16GB heap
- **Security**: Disabled (development)
- **Discovery**: Single node

## 🔒 **Security**

### **Production Checklist**
- [ ] Enable Elasticsearch security
- [ ] Set strong passwords
- [ ] Configure SSL/TLS
- [ ] Restrict network access
- [ ] Enable authentication cho monitoring

### **Development Setup**
- Security disabled cho dễ test
- Passwords mặc định: `Shopsifu2025`
- Network: Docker internal only

## 📁 **Cấu trúc thư mục**

```
.
├── config/                 # Cấu hình services
│   ├── elasticsearch.yml   # Elasticsearch config
│   ├── postgresql.conf     # PostgreSQL config
│   ├── redis.conf         # Redis config
│   ├── pgbouncer.ini      # PgBouncer config
│   ├── grafana.ini        # Grafana config
│   └── kibana.yml         # Kibana config
├── monitoring/             # Monitoring configs
│   ├── prometheus/         # Prometheus config
│   └── grafana/            # Grafana config
├── logs/                   # Application logs
├── certs/                  # SSL certificates
├── upload/                 # User uploads
├── docker-compose.swarm.yml # Docker Swarm compose
├── .env.docker             # Docker environment
└── README.md               # This file
```

## 🚨 **Troubleshooting**

### **Service không khởi động**
```bash
# Kiểm tra logs
docker service logs shopsifu_server

# Kiểm tra trạng thái
docker service ps shopsifu_server

# Restart service
docker service update --force shopsifu_server
```

### **Database connection issues**
```bash
# Kiểm tra PostgreSQL
docker service logs shopsifu_postgres

# Kiểm tra PgBouncer
docker service logs shopsifu_pgbouncer

# Test connection
docker exec -it $(docker ps -q -f name=postgres) pg_isready -U shopsifu
```

### **Elasticsearch issues**
```bash
# Kiểm tra logs
docker service logs shopsifu_elasticsearch

# Kiểm tra health
curl http://localhost:9200/_cluster/health

# Reset password (nếu cần)
docker exec -it $(docker ps -q -f name=elasticsearch) /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i
```

## 📈 **Performance Tuning**

### **Server Optimization**
- **Workers**: 3 replicas (6 cores, 12GB RAM mỗi replica)
- **Thread Pool**: 40 threads per replica
- **Memory**: 12GB heap per replica
- **Concurrency**: 3000 requests per replica

### **Database Optimization**
- **Connection Pool**: 20-100 connections
- **Shared Buffers**: 8GB
- **Effective Cache**: 20GB
- **Work Memory**: 32MB

### **Cache Optimization**
- **Memory**: 20GB
- **IO Threads**: 8
- **Persistence**: AOF + RDB
- **Eviction**: noeviction

## 🤝 **Contributing**

1. Fork repository
2. Tạo feature branch
3. Commit changes
4. Push to branch
5. Tạo Pull Request

## 📄 **License**

MIT License - xem file [LICENSE](LICENSE) để biết thêm chi tiết.

## 📞 **Support**

- **Email**: shopsifu.ecommerce@gmail.com
- **Issues**: GitHub Issues
- **Documentation**: Wiki

---

**Made with ❤️ by ShopSifu Team**
