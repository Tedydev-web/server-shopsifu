# Mục đích dự án
Backend thương mại điện tử Shopsifu (NestJS) quản lý người dùng, quyền/role, sản phẩm, danh mục, giỏ hàng, đơn hàng, thanh toán (VNPay, SePay), mã giảm giá, đánh giá, tìm kiếm (Elasticsearch), realtime qua WebSocket, và quan sát hệ thống (Prometheus/Grafana).

# Entrypoints
- Ứng dụng: `src/main.ts` khởi chạy `AppModule`.
- Module gốc: `src/app.module.ts` ghép các route-modules, global pipes/filters/interceptors/guards, cronjobs.

# Hạ tầng/phụ trợ
- CSDL: PostgreSQL qua Prisma. Kết nối pool qua PgBouncer (docker-compose).
- Cache/Queue/WS adapter: Redis (ioredis, BullMQ).
- Tìm kiếm: Elasticsearch 8 (client `@elastic/elasticsearch`).
- Giám sát: Prometheus, Grafana (docker-compose), Terminus health checks.
- Log/quan sát: nestjs-pino; Kibana (kết nối ES) trong docker-compose.

# Miền nghiệp vụ chính
- `auth`, `user`, `role`, `permission`, `brand`, `category`, `product` (+ translation, sku), `cart`, `order`, `payment` (vnpay, sepay), `discount`, `review`, `search`, `profile`, `language`.
- Cronjobs: hết hạn giảm giá, dọn refresh token, precompute home feed.
- Websocket: `src/websockets/*` (Socket.IO + Redis adapter).