# 🛒 Order Management API

## 📋 Tổng quan

Hệ thống quản lý đơn hàng cho phép:
- **Users**: Xem đơn hàng của mình
- **Sellers**: Quản lý đơn hàng của shop mình
- **Admins**: Quản lý tất cả đơn hàng

## 🚀 API Endpoints

### **Public API (Users)**
```
GET    /orders                    # Danh sách đơn hàng của user
GET    /orders/:orderId          # Chi tiết đơn hàng
```

### **Manage API (Sellers)**
```
GET    /manage-order/orders                    # Danh sách đơn hàng của shop
GET    /manage-order/orders/:orderId          # Chi tiết đơn hàng
PATCH  /manage-order/orders/:orderId/status  # Cập nhật trạng thái đơn hàng
```

## 🔐 Phân quyền

| Role | Endpoint | Quyền |
|------|----------|-------|
| **CLIENT** | `/orders/*` | Xem đơn hàng của mình |
| **SELLER** | `/manage-order/orders/*` | Quản lý đơn hàng shop mình |
| **ADMIN** | `/manage-order/orders/*` | Quản lý tất cả đơn hàng |

## 📊 Order Status Flow

```
PENDING_PAYMENT → PENDING_PICKUP → PENDING_DELIVERY → DELIVERED
       ↓                ↓                ↓
    CANCELLED      CANCELLED        RETURNED
```

## 🔍 Query Parameters

### **List Orders**
```typescript
{
  page?: number           // Trang hiện tại (default: 1)
  limit?: number          // Số item/trang (default: 10)
  startDate?: string      // Ngày bắt đầu (ISO string)
  endDate?: string        // Ngày kết thúc (ISO string)
  customerName?: string   // Tên khách hàng
  orderCode?: string      // Mã đơn hàng
  status?: OrderStatus    // Trạng thái đơn hàng
}
```

### **Update Status (PATCH)**
```typescript
{
  status: OrderStatus    // Trạng thái mới (bắt buộc)
  note?: string         // Ghi chú khi thay đổi trạng thái
}
```

## 📝 Response Format

### **Success Response**
```typescript
{
  statusCode: 200,
  message: "Thành công",
  timestamp: "2025-08-24T08:00:00.000Z",
  data: OrderData | OrderListData,
  metadata?: PaginationMetadata
}
```

### **Error Response**
```typescript
{
  statusCode: 400 | 401 | 403 | 404 | 500,
  message: "Lỗi mô tả",
  error: "Error Type",
  timestamp: "2025-08-24T08:00:00.000Z"
}
```

## 🏗️ Project Structure

```
src/routes/order/
├── order.module.ts              # Main module
├── order.controller.ts          # Public API
├── order.service.ts            # Public service
├── order.repo.ts              # Repository
├── manage-order/               # Seller management
│   ├── manage-order.controller.ts
│   ├── manage-order.service.ts
│   ├── manage-order.dto.ts
│   └── manage-order.model.ts
└── README.md
```

## ✅ Best Practices Implemented

### **1. RESTful API Design**
- ✅ `GET /orders` - List resources
- ✅ `GET /orders/:id` - Get single resource
- ✅ `PATCH /orders/:id/status` - Partial update

### **2. Module Architecture**
- ✅ Single module pattern (giống Product)
- ✅ Clear separation of concerns
- ✅ Repository pattern
- ✅ Service layer business logic

### **3. Security & Validation**
- ✅ Role-based access control
- ✅ Input validation với Zod
- ✅ Seller privilege validation
- ✅ Status transition validation (TODO)

### **4. Error Handling**
- ✅ Consistent error responses
- ✅ Proper HTTP status codes
- ✅ User-friendly error messages

## 🚧 TODO & Future Improvements

- [ ] Implement status transition validation
- [ ] Add order history tracking
- [ ] Add bulk status updates
- [ ] Add order notifications
- [ ] Add order analytics
- [ ] Add order export functionality

## 🔗 Related APIs

- **Product API**: `/products/*`
- **User API**: `/users/*`
- **Payment API**: `/payment/*`
- **Shipping API**: `/shipping/*`
