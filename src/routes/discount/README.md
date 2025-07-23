# Discount Module API

Tài liệu này mô tả chi tiết các endpoint của module Discount, giúp frontend hiểu rõ cách sử dụng, các trường hợp hỗ trợ, quyền hạn, tham số, luồng hoạt động và các lưu ý đặc biệt.

## 1. Phân quyền & Vai trò

- **Admin**: Toàn quyền với mọi discount (toàn sàn hoặc của bất kỳ shop nào).
- **Seller**: Chỉ thao tác với discount của shop mình (shopId = userId).
- **Client/Guest**: Chỉ xem, áp dụng, kiểm tra mã giảm giá.

---

## 2. Public Endpoints (Client/Guest)

**Base Path:** `/discounts`

### 2.1. GET `/discounts/available`
- **Mục đích:** Lấy tất cả voucher có thể áp dụng cho user hiện tại (theo shop, sản phẩm, giá trị đơn hàng, ...).
- **Query Params:**
  | Tên        | Kiểu     | Bắt buộc | Mặc định | Ý nghĩa |
  |------------|----------|----------|----------|---------|
  | shopId     | string   | Không    | null     | Lọc theo shop, null = toàn sàn |
  | orderValue | number   | Không    | 0        | Giá trị đơn hàng hiện tại |
  | productId  | string   | Không    |          | Lọc theo sản phẩm cụ thể |
  | isPublic   | boolean  | Không    | true     | Chỉ lấy voucher public |
  | status     | string   | Không    | 'ACTIVE' | Lọc theo trạng thái voucher |
  | page       | number   | Không    | 1        | Trang (phân trang) |
  | limit      | number   | Không    | 10       | Số lượng/trang |
- **Luồng hoạt động:**
  1. FE gửi request kèm các query params phù hợp context (shopId, orderValue, productId...).
  2. BE trả về 2 mảng: `available` (voucher có thể dùng), `unavailable` (voucher không dùng được, kèm lý do).
  3. FE hiển thị danh sách, highlight voucher tốt nhất (`isBestChoice`).

### 2.2. POST `/discounts/verify`
- **Mục đích:** Kiểm tra mã giảm giá có hợp lệ không, tính toán số tiền được giảm.
- **Request body:**
  | Tên      | Kiểu     | Bắt buộc | Ý nghĩa |
  |----------|----------|----------|---------|
  | code     | string   | Có       | Mã voucher cần kiểm tra |
  | orderValue | number | Có       | Giá trị đơn hàng hiện tại |
  | cart     | array    | Không    | Thông tin chi tiết giỏ hàng (shopId, productId, quantity, price) |
- **Ví dụ JSON:**
```json
{
  "code": "SUMMER2024",
  "orderValue": 500000,
  "cart": [
    { "shopId": "shop1", "productId": "prod1", "quantity": 2, "price": 250000 },
    { "shopId": "shop2", "productId": "prod2", "quantity": 1, "price": 100000 }
  ]
}
```
- **Luồng hoạt động:**
  1. FE gửi mã code, giá trị đơn hàng, giỏ hàng (nếu có).
  2. BE kiểm tra điều kiện, trả về số tiền giảm và thông tin voucher.
  3. Nếu không hợp lệ, trả về lỗi hoặc thông báo.

### 2.3. GET `/discounts/:discountId`
- **Mục đích:** Lấy chi tiết 1 voucher public.
- **Luồng hoạt động:**
  1. FE gửi request với discountId.
  2. BE trả về thông tin chi tiết voucher.

---

## 3. Management Endpoints (Admin/Seller)

**Base Path:** `/manage-discount/discounts`

### 3.1. GET `/manage-discount/discounts`
- **Mục đích:** Lấy danh sách voucher quản lý (phân trang, filter).
- **Query Params:**
  | Tên        | Kiểu     | Bắt buộc | Mặc định | Ý nghĩa |
  |------------|----------|----------|----------|---------|
  | shopId     | string   | Không    | null     | Lọc theo shop |
  | isPublic   | boolean  | Không    |          | Lọc public/private |
  | status     | enum     | Không    |          | Trạng thái (ACTIVE, INACTIVE, ...) |
  | search     | string   | Không    |          | Tìm kiếm theo tên |
  | page       | number   | Không    | 1        | Trang |
  | limit      | number   | Không    | 10       | Số lượng/trang |
- **Luồng hoạt động:**
  1. FE gửi request với các filter phù hợp.
  2. BE trả về danh sách voucher, phân trang.

### 3.2. POST `/manage-discount/discounts`
- **Mục đích:** Tạo mới voucher.
- **Request body:**
  | Tên              | Kiểu     | Bắt buộc | Ý nghĩa |
  |------------------|----------|----------|---------|
  | name             | string   | Có       | Tên voucher |
  | description      | string   | Không    | Mô tả |
  | type             | enum     | Có       | Loại voucher (PERCENT, FIX_AMOUNT) |
  | value            | number   | Có       | Giá trị giảm giá |
  | code             | string   | Có       | Mã code |
  | startDate        | string   | Có       | Ngày bắt đầu |
  | endDate          | string   | Có       | Ngày kết thúc |
  | maxUses          | number   | Không    | Số lượt dùng tối đa |
  | maxUsesPerUser   | number   | Không    | Số lượt dùng tối đa/user |
  | minOrderValue    | number   | Không    | Giá trị đơn hàng tối thiểu |
  | canSaveBeforeStart | boolean | Không    | Cho phép lưu trước khi bắt đầu |
  | isPublic         | boolean  | Không    | Public/private |
  | status           | enum     | Không    | Trạng thái |
  | appliesTo        | enum     | Có       | Áp dụng cho (ALL, SPECIFIC) |
  | maxDiscountValue | number   | Không    | Mức giảm tối đa (chỉ cho PERCENT) |
  | shopId           | string   | Không    | Shop áp dụng (admin truyền, seller tự động) |
  | products         | array    | Không    | Danh sách sản phẩm áp dụng |
  | categories       | array    | Không    | Danh sách danh mục áp dụng |
  | brands           | array    | Không    | Danh sách thương hiệu áp dụng |
- **Ví dụ JSON:**
```json
{
  "name": "Voucher 10% toàn shop",
  "description": "Giảm 10% cho đơn từ 200k",
  "type": "PERCENT",
  "value": 10,
  "code": "SHOP10",
  "startDate": "2024-06-01T00:00:00.000Z",
  "endDate": "2024-06-30T23:59:59.000Z",
  "maxUses": 1000,
  "maxUsesPerUser": 2,
  "minOrderValue": 200000,
  "canSaveBeforeStart": true,
  "isPublic": true,
  "status": "ACTIVE",
  "appliesTo": "ALL",
  "maxDiscountValue": 50000,
  "shopId": "shop1",
  "products": ["prod1", "prod2"],
  "categories": ["cat1"],
  "brands": ["brand1"]
}
```
- **Luồng hoạt động:**
  1. FE gửi đầy đủ thông tin voucher.
  2. BE kiểm tra quyền, validate dữ liệu, tạo mới voucher.

### 3.3. PUT `/manage-discount/discounts/:discountId`
- **Mục đích:** Cập nhật voucher.
- **Request body:** Giống như tạo mới, các trường partial (không bắt buộc truyền hết).
- **Ví dụ JSON:**
```json
{
  "name": "Voucher 15% toàn shop",
  "value": 15,
  "endDate": "2024-07-31T23:59:59.000Z",
  "status": "INACTIVE"
}
```
- **Luồng hoạt động:**
  1. FE gửi thông tin cần cập nhật.
  2. BE kiểm tra quyền, validate, cập nhật.

### 3.4. DELETE `/manage-discount/discounts/:discountId`
- **Mục đích:** Xóa mềm voucher.
- **Luồng hoạt động:**
  1. FE gửi request xóa.
  2. BE kiểm tra quyền, xóa mềm.

---

## 4. Flow hoạt động tổng quát

### 4.1. Client/Guest
- Lấy danh sách voucher khả dụng: Gọi `/discounts/available` → Hiển thị danh sách, chọn voucher tốt nhất.
- Kiểm tra mã voucher: Gọi `/discounts/verify` khi user nhập code → Hiển thị kết quả hợp lệ/số tiền giảm.
- Xem chi tiết voucher: Gọi `/discounts/:discountId` khi cần xem chi tiết.

### 4.2. Seller/Admin
- Quản lý voucher:
  - Gọi `/manage-discount/discounts` để xem danh sách, filter, search.
  - Gọi `POST` để tạo mới, `PUT` để cập nhật, `DELETE` để xóa voucher.
  - Khi tạo/cập nhật voucher áp dụng cho sản phẩm, phải truyền đúng danh sách sản phẩm thuộc shop mình.

---

## 5. Lưu ý & Quy tắc đặc biệt

- Seller chỉ thao tác với voucher của shop mình.
- Admin có thể thao tác với mọi voucher.
- Khi tạo/cập nhật voucher áp dụng cho sản phẩm, phải truyền đúng danh sách sản phẩm hợp lệ.
- Các trường hợp lỗi sẽ trả về message rõ ràng, FE cần hiển thị cho user.
- Các trường hợp không tìm thấy voucher sẽ trả về mảng rỗng, không trả 404.
