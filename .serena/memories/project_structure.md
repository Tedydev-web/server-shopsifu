# Cấu trúc chi tiết dự án

## Cấu trúc thư mục chính
```
server-shopsifu/
├── src/
│   ├── routes/           # API modules
│   │   ├── auth/         # Authentication
│   │   ├── user/         # User management
│   │   ├── product/      # Product management
│   │   ├── cart/         # Shopping cart
│   │   ├── order/        # Order management
│   │   ├── payment/      # Payment gateways
│   │   ├── brand/        # Brand management
│   │   ├── category/     # Category management
│   │   ├── discount/     # Discount system
│   │   ├── review/       # Review system
│   │   ├── media/        # File uploads
│   │   ├── permission/   # Permission system
│   │   ├── role/         # Role management
│   │   ├── profile/      # User profile
│   │   └── language/     # Language management
│   ├── shared/           # Shared module
│   │   ├── config/       # Configuration
│   │   ├── services/     # Shared services
│   │   ├── guards/       # Authentication guards
│   │   ├── filters/      # Exception filters
│   │   ├── interceptors/ # Response interceptors
│   │   ├── decorators/   # Custom decorators
│   │   ├── dtos/         # Shared DTOs
│   │   ├── models/       # Shared models
│   │   ├── constants/    # Constants
│   │   ├── enums/        # Enums
│   │   ├── types/        # Type definitions
│   │   ├── languages/    # i18n translations
│   │   ├── queues/       # Queue consumers
│   │   ├── repositories/ # Shared repositories
│   │   ├── pipes/        # Custom pipes
│   │   └── producers/    # Queue producers
│   ├── websockets/       # WebSocket implementation
│   ├── cronjobs/         # Scheduled tasks
│   ├── main.ts           # Application entry point
│   ├── app.module.ts     # Root module
│   └── types.ts          # Global types
├── prisma/               # Database schema và migrations
├── initialScript/        # Initial data scripts
├── docs/                 # Documentation
└── test/                 # Test files
```

## Database Schema (Prisma)
- **User**: Quản lý người dùng với roles và permissions
- **Product**: Sản phẩm với SKUs và translations
- **Category**: Danh mục sản phẩm với translations
- **Brand**: Thương hiệu với translations
- **Order**: Đơn hàng với payment transactions
- **Cart**: Giỏ hàng
- **Review**: Đánh giá sản phẩm
- **Discount**: Hệ thống khuyến mãi
- **Payment**: Thanh toán
- **Language**: Quản lý đa ngôn ngữ

## Key Features
- **Authentication**: JWT + TOTP 2FA
- **Authorization**: Role-based access control
- **File Upload**: AWS S3 integration
- **Payment**: VNPay, Sepay integration
- **Real-time**: WebSocket với Socket.io
- **Queue**: Background jobs với BullMQ
- **Caching**: Redis integration
- **Internationalization**: i18n support
- **Scheduling**: Cron jobs
- **Email**: React Email templates