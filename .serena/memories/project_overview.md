# Tổng quan dự án Shopsifu

## Mục đích dự án
Shopsifu là một ứng dụng e-commerce backend được xây dựng bằng NestJS, cung cấp API cho hệ thống thương mại điện tử với các tính năng:
- Quản lý người dùng và xác thực
- Quản lý sản phẩm, danh mục, thương hiệu
- Quản lý giỏ hàng và đơn hàng
- Hệ thống thanh toán (VNPay, Sepay)
- Quản lý đánh giá và review
- Hệ thống khuyến mãi và giảm giá
- Đa ngôn ngữ (i18n)
- WebSocket cho real-time communication

## Tech Stack
- **Framework**: NestJS (Node.js)
- **Database**: PostgreSQL với Prisma ORM
- **Cache**: Redis
- **Queue**: BullMQ
- **Authentication**: JWT, TOTP (2FA)
- **File Storage**: AWS S3
- **Payment**: VNPay, Sepay
- **Email**: Resend với React Email
- **WebSocket**: Socket.io
- **Validation**: Zod, class-validator
- **Testing**: Jest
- **Build Tool**: SWC
- **Code Quality**: ESLint, Prettier

## Cấu trúc dự án
```
src/
├── routes/           # Các module API
│   ├── auth/        # Xác thực
│   ├── user/        # Quản lý người dùng
│   ├── product/     # Sản phẩm
│   ├── cart/        # Giỏ hàng
│   ├── order/       # Đơn hàng
│   ├── payment/     # Thanh toán
│   └── ...
├── shared/          # Module chia sẻ
│   ├── config/      # Cấu hình
│   ├── services/    # Dịch vụ chia sẻ
│   ├── guards/      # Guards
│   ├── filters/     # Exception filters
│   └── ...
├── websockets/      # WebSocket
└── cronjobs/        # Cron jobs
```