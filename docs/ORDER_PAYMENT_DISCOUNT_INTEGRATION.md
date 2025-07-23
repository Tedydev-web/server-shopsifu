# Tài liệu Kỹ thuật: Order, Payment và Tích hợp Discount

## Mục lục
1. [Giới thiệu](#giới-thiệu)
2. [Kiến trúc hệ thống](#kiến-trúc-hệ-thống)
3. [Mô hình dữ liệu](#mô-hình-dữ-liệu)
4. [Flow hoạt động](#flow-hoạt-động)
5. [Tích hợp Discount](#tích-hợp-discount)
6. [API Endpoints](#api-endpoints)
7. [Bảo mật dữ liệu tài chính](#bảo-mật-dữ-liệu-tài-chính)
8. [Xử lý đồng thời](#xử-lý-đồng-thời)
9. [Logging và Debugging](#logging-và-debugging)
10. [Testcases](#testcases)

## Giới thiệu

Tài liệu này mô tả chi tiết về hệ thống Order, Payment và việc tích hợp Discount trong dự án Shopsifu. Hệ thống được xây dựng trên nền tảng NestJS với Prisma ORM và cơ sở dữ liệu PostgreSQL.

### Mục tiêu
- Xây dựng hệ thống order-payment hoàn chỉnh cho nền tảng multi-vendor
- Tích hợp hệ thống giảm giá (discount) linh hoạt
- Đảm bảo tính toàn vẹn dữ liệu tài chính
- Cung cấp trải nghiệm mua sắm mượt mà cho người dùng

## Kiến trúc hệ thống

### Công nghệ sử dụng
- **Backend**: NestJS (Node.js framework)
- **Database**: PostgreSQL
- **ORM**: Prisma
- **Queue**: BullMQ (xử lý các tác vụ nền)
- **Lock**: Redlock (xử lý đồng thời)
- **Payment Gateway**: SePay (giả lập)

### Các module chính
1. **Order Module**: Quản lý đơn hàng và luồng xử lý
2. **Payment Module**: Xử lý thanh toán và webhook
3. **Cart Module**: Quản lý giỏ hàng
4. **Discount Module**: Quản lý mã giảm giá và áp dụng

## Mô hình dữ liệu

### Cấu trúc cơ sở dữ liệu
Dưới đây là các model chính liên quan đến Order, Payment và Discount:

#### Order Model
```prisma
model Order {
  id          String               @id @default(uuid())
  userId      String
  user        User                 @relation(fields: [userId], references: [id], onDelete: NoAction, onUpdate: NoAction)
  status      OrderStatus
  items       ProductSKUSnapshot[]
  products    Product[]
  reviews     Review[]
  receiver    Json
  shopId      String?
  shop        User?                @relation("Shop", fields: [shopId], references: [id], onDelete: SetNull, onUpdate: NoAction)
  paymentId   String
  payment     Payment              @relation(fields: [paymentId], references: [id], onDelete: NoAction, onUpdate: NoAction)
  discounts   DiscountSnapshot[]
  // Audit fields
  createdById String?
  createdBy   User?                @relation("OrderCreatedBy", fields: [createdById], references: [id], onDelete: SetNull, onUpdate: NoAction)
  updatedById String?
  updatedBy   User?                @relation("OrderUpdatedBy", fields: [updatedById], references: [id], onDelete: SetNull, onUpdate: NoAction)
  deletedById String?
  deletedBy   User?                @relation("OrderDeletedBy", fields: [deletedById], references: [id], onDelete: SetNull, onUpdate: NoAction)
  deletedAt   DateTime?
  createdAt   DateTime             @default(now())
  updatedAt   DateTime             @updatedAt

  @@index([deletedAt])
  @@index([status, deletedAt])
}
```

#### ProductSKUSnapshot Model
```prisma
model ProductSKUSnapshot {
  id            String  @id @default(uuid())
  skuId         String
  name          String  @db.VarChar(500)
  description   String?
  price         Int
  originalPrice Int
  quantity      Int
  options       Json?
  orderId       String?
  order         Order?  @relation(fields: [orderId], references: [id], onDelete: SetNull, onUpdate: NoAction)

  deletedAt DateTime?
  createdAt DateTime  @default(now())
  updatedAt DateTime  @updatedAt

  @@index([deletedAt])
}
```

#### DiscountSnapshot Model
```prisma
model DiscountSnapshot {
  id               String       @id @default(uuid())
  name             String       @db.VarChar(500)
  description      String?      @db.VarChar(1000)
  type             DiscountType
  value            Int
  code             String       @db.VarChar(100)
  maxDiscountValue Int?
  discountAmount   Int // Số tiền thực tế đã giảm

  minOrderValue Int
  isPublic      Boolean
  appliesTo     DiscountApplyType
  targetInfo    Json? // thông tin đối tượng áp dụng

  discountId String?
  discount   Discount? @relation(fields: [discountId], references: [id], onDelete: SetNull, onUpdate: NoAction)

  orderId String?
  order   Order?  @relation(fields: [orderId], references: [id], onDelete: SetNull, onUpdate: NoAction)

  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  @@index([orderId])
  @@index([discountId])
}
```

#### Discount Model
```prisma
model Discount {
  id               String       @id @default(uuid())
  name             String       @db.VarChar(500)
  description      String?      @default("")
  type             DiscountType @default(FIX_AMOUNT)
  value            Int
  code             String       @unique @db.VarChar(100)
  startDate        DateTime
  endDate          DateTime
  maxUses          Int          @default(0) // 0 is unlimited
  usesCount        Int          @default(0)
  usersUsed        String[]
  maxUsesPerUser   Int          @default(0) // 0 is unlimited
  minOrderValue    Int          @default(0)
  maxDiscountValue Int? // Đối với chiết khấu theo tỷ lệ phần trăm
  isPublic         Boolean      @default(true)
  shopId           String?
  shop             User?        @relation("ShopDiscounts", fields: [shopId], references: [id], onDelete: SetNull, onUpdate: NoAction)

  status    DiscountStatus    @default(DRAFT)
  appliesTo DiscountApplyType @default(ALL)
  products  Product[]

  categories Category[]
  brands     Brand[]

  discountSnapshots DiscountSnapshot[]

  // Audit fields
  createdById String?
  createdBy   User?              @relation("DiscountCreatedBy", fields: [createdById], references: [id], onDelete: SetNull, onUpdate: NoAction)
  updatedById String?
  updatedBy   User?              @relation("DiscountUpdatedBy", fields: [updatedById], references: [id], onDelete: SetNull, onUpdate: NoAction)
  deletedById String?
  deletedBy   User?              @relation("DiscountDeletedBy", fields: [deletedById], references: [id], onDelete: SetNull, onUpdate: NoAction)

  deletedAt DateTime?
  createdAt DateTime  @default(now())
  updatedAt DateTime  @updatedAt

  @@index([deletedAt])
  @@index([status, deletedAt])
  @@index([startDate, endDate])
}
```

#### Payment Model
```prisma
model Payment {
  id        String        @id @default(uuid())
  orders    Order[]
  status    PaymentStatus
  createdAt DateTime      @default(now())
  updatedAt DateTime      @updatedAt
}
```

### Enums và Types
```prisma
enum OrderStatus {
  PENDING_PAYMENT
  PENDING_PICKUP
  PENDING_DELIVERY
  DELIVERED
  RETURNED
  CANCELLED
}

enum PaymentStatus {
  PENDING
  SUCCESS
  FAILED
}

enum DiscountType {
  FIX_AMOUNT
  PERCENTAGE
}

enum DiscountStatus {
  DRAFT
  INACTIVE
  ACTIVE
  EXPIRED
}

enum DiscountApplyType {
  ALL
  SPECIFIC
}
```

## Flow hoạt động

### Quá trình tạo đơn hàng
1. **Thêm sản phẩm vào giỏ hàng**
   - User thêm sản phẩm vào giỏ hàng (CartItem)
   - Mỗi CartItem liên kết với một SKU và số lượng

2. **Checkout**
   - User chọn sản phẩm từ giỏ hàng để checkout
   - Hệ thống tính toán giá trị đơn hàng và kiểm tra tính khả dụng

3. **Áp dụng mã giảm giá**
   - User nhập mã giảm giá (nếu có)
   - Hệ thống kiểm tra tính hợp lệ của mã giảm giá
   - Tính toán lại giá trị đơn hàng

4. **Tạo đơn hàng**
   - Tạo bản ghi Payment với trạng thái PENDING
   - Tạo bản ghi Order với thông tin người nhận
   - Tạo các ProductSKUSnapshot để lưu giữ thông tin sản phẩm tại thời điểm đặt hàng
   - Tạo các DiscountSnapshot để lưu giữ thông tin giảm giá đã áp dụng
   - Xóa các sản phẩm đã được đặt hàng khỏi giỏ hàng

5. **Thanh toán**
   - Chuyển hướng user đến cổng thanh toán
   - Cổng thanh toán thông báo kết quả qua webhook

6. **Cập nhật trạng thái**
   - Hệ thống nhận webhook và cập nhật trạng thái đơn hàng
   - Nếu thanh toán thành công: Order.status = PENDING_PICKUP
   - Nếu thanh toán thất bại: Order.status = CANCELLED

## Tích hợp Discount

### Kiến trúc Discount
Hệ thống discount được thiết kế với các đặc điểm sau:
- Hỗ trợ nhiều loại giảm giá (cố định, phần trăm)
- Phạm vi áp dụng linh hoạt (toàn bộ đơn hàng, sản phẩm cụ thể, danh mục, nhãn hiệu)
- Điều kiện áp dụng (giá trị đơn hàng tối thiểu, giảm giá tối đa)
- Giới hạn sử dụng (số lần sử dụng tối đa, số lần sử dụng tối đa mỗi user)
- Thời gian áp dụng (ngày bắt đầu, ngày kết thúc)

### Snapshot Pattern
Chúng tôi sử dụng mô hình "Snapshot" để lưu trữ thông tin giảm giá tại thời điểm đặt hàng:
- **Lý do**: Các thông tin về discount có thể thay đổi theo thời gian, nhưng giá trị đã áp dụng cho đơn hàng cần được giữ nguyên
- **Cách thức**: Khi tạo đơn hàng, thông tin discount được sao chép từ Discount vào DiscountSnapshot
- **Lợi ích**: Bảo toàn tính toàn vẹn dữ liệu tài chính và lịch sử giao dịch

### Quy trình áp dụng discount
1. **Kiểm tra mã giảm giá**
   - Validate mã giảm giá (tồn tại, còn thời hạn, số lượng còn lại)
   - Kiểm tra điều kiện áp dụng (giá trị đơn hàng tối thiểu)

2. **Tính toán giảm giá**
   - Xác định các sản phẩm được áp dụng giảm giá
   - Tính toán giá trị giảm giá dựa trên loại (FIX_AMOUNT hoặc PERCENTAGE)
   - Áp dụng giới hạn giảm giá tối đa (nếu có)

3. **Lưu trữ thông tin**
   - Tạo DiscountSnapshot khi đơn hàng được xác nhận
   - Cập nhật số lượng sử dụng của discount

## API Endpoints

### Cart APIs
```
GET /cart - Lấy thông tin giỏ hàng của user
POST /cart - Thêm sản phẩm vào giỏ hàng
PUT /cart/:id - Cập nhật số lượng sản phẩm trong giỏ hàng
DELETE /cart/:id - Xóa sản phẩm khỏi giỏ hàng
```

### Order APIs
```
POST /orders/checkout - Checkout từ giỏ hàng và tạo đơn hàng
POST /orders/calculate - Tính toán giá trị đơn hàng (bao gồm discount)
GET /orders - Lấy danh sách đơn hàng
GET /orders/:id - Lấy chi tiết đơn hàng
PATCH /orders/:id/status - Cập nhật trạng thái đơn hàng
```

### Payment APIs
```
POST /payment/sepay/webhook - Webhook nhận thông báo kết quả thanh toán từ SePay
```

### Discount APIs
```
POST /discounts/validate - Kiểm tra tính hợp lệ của mã giảm giá
POST /discounts/available-for-checkout - Lấy danh sách mã giảm giá có thể áp dụng cho giỏ hàng
```

## Bảo mật dữ liệu tài chính

### Snapshot Pattern
Hệ thống sử dụng "Snapshot Pattern" để đảm bảo tính toàn vẹn dữ liệu tài chính:
- ProductSKUSnapshot: lưu giữ thông tin giá cả sản phẩm tại thời điểm đặt hàng
- DiscountSnapshot: lưu giữ thông tin giảm giá đã áp dụng

### Transaction
Các thao tác liên quan đến tài chính đều được thực hiện trong transaction để đảm bảo tính atomicity:
- Tạo đơn hàng và các liên kết (order items, payment)
- Áp dụng discount và tạo snapshot
- Cập nhật số lượng discount đã sử dụng
