# Discount API Documentation

## Mục lục
- [1. CRUD Discount (ADMIN/SELLER)](#crud-discount-adminseller)
  - [1.1. Tạo mới discount](#tạo-mới-discount)
  - [1.2. Lấy danh sách discount](#lấy-danh-sách-discount)
  - [1.3. Lấy chi tiết discount](#lấy-chi-tiết-discount)
  - [1.4. Cập nhật discount](#cập-nhật-discount)
  - [1.5. Xóa discount](#xóa-discount)
- [2. CLIENT/GUEST: Lấy voucher khả dụng, verify/apply voucher](#clientguest-lấy-voucher-khả-dụng-verifyapply-voucher)
  - [2.1. Lấy voucher khả dụng](#lấy-voucher-khả-dụng)
  - [2.2. Verify/apply voucher](#verifyapply-voucher)
- [3. Ghi chú về phân quyền, validate, UI mapping](#ghi-chú-về-phân-quyền-validate-ui-mapping)

---

## 1. CRUD Discount (ADMIN/SELLER)

### 1.1. Tạo mới discount
- **Endpoint:** `POST /discounts`
- **Role:** ADMIN, SELLER
- **Body:**
```json
{
  "name": "Voucher 20k",
  "description": "Giảm 20k cho đơn từ 200k",
  "type": "FIX_AMOUNT", // hoặc "PERCENTAGE"
  "value": 20000,
  "code": "SALE20K",
  "startDate": "2024-07-01T00:00:00.000Z",
  "endDate": "2024-07-31T23:59:59.000Z",
  "maxUses": 1000,
  "maxUsesPerUser": 2,
  "minOrderValue": 200000,
  "canSaveBeforeStart": true,
  "isPublic": true,
  "shopId": "...", // ADMIN có thể để null (toàn sàn), SELLER là shop của mình
  "status": "ACTIVE",
  "appliesTo": "ALL" // hoặc "SPECIFIC"
}
```
- **Response:**
```json
{
  "id": "...",
  ... // các trường discount
}
```
- **UI sử dụng:** Form tạo voucher cho ADMIN/SELLER

---

### 1.2. Lấy danh sách discount
- **Endpoint:** `GET /discounts`
- **Role:** ADMIN, SELLER, CLIENT
- **Query params:**
  - `page`, `limit`, `shopId`, `isPublic`, `status`, `search`
- **Ví dụ:** `/discounts?page=1&limit=10&shopId=...&status=ACTIVE`
- **Response:**
```json
{
  "message": "...",
  "data": [ { ...discount }, ... ],
  "metadata": { "totalItems": 100, "page": 1, "limit": 10, ... }
}
```
- **UI sử dụng:** Danh sách voucher, filter, phân trang

---

### 1.3. Lấy chi tiết discount
- **Endpoint:** `GET /discounts/:discountId`
- **Role:** ADMIN, SELLER, CLIENT
- **Response:**
```json
{
  "message": "...",
  "data": { ...discount }
}
```
- **UI sử dụng:** Xem chi tiết voucher

---

### 1.4. Cập nhật discount
- **Endpoint:** `PUT /discounts/:discountId`
- **Role:** ADMIN, SELLER
- **Body:** (các trường giống tạo mới, có thể partial)
- **Response:**
```json
{
  ... // discount đã cập nhật
}
```
- **UI sử dụng:** Form chỉnh sửa voucher

---

### 1.5. Xóa discount
- **Endpoint:** `DELETE /discounts/:discountId`
- **Role:** ADMIN, SELLER
- **Query:** `isHard` (nếu muốn xóa cứng)
- **Response:**
```json
{
  ... // discount đã xóa (mềm/hard)
}
```
- **UI sử dụng:** Xóa voucher

---

## 2. CLIENT/GUEST: Lấy voucher khả dụng, verify/apply voucher

### 2.1. Lấy voucher khả dụng
- **Endpoint:** `GET /discounts/available`
- **Role:** CLIENT, GUEST
- **Query params:**
  - `shopId`, `productId`, `orderValue`, `cart` (JSON.stringify array sản phẩm)
- **Ví dụ:** `/discounts/available?shopId=...&orderValue=300000&productId=...`
- **Response:**
```json
{
  "available": [ { ...discount }, ... ],
  "unavailable": [ { ...discount, reason: "Hết lượt dùng" }, ... ]
}
```
- **UI sử dụng:**
  - Popup chọn voucher trong cart/order
  - Hiển thị voucher khả dụng/không khả dụng

---

### 2.2. Verify/apply voucher
- **Endpoint:** `POST /discounts/verify`
- **Role:** CLIENT
- **Body:**
```json
{
  "code": "SALE20K",
  "orderValue": 300000,
  "productIds": ["..."],
  "apply": true, // hoặc false nếu chỉ muốn kiểm tra
  "cart": [
    { "shopId": "...", "productId": "...", "quantity": 2, "price": 150000 },
    ...
  ]
}
```
- **Response:**
```json
{
  "discountAmount": 20000,
  "voucher": { "code": "SALE20K", "type": "FIX_AMOUNT", "value": 20000, ... }
}
```
- **UI sử dụng:**
  - Khi CLIENT nhập mã voucher, nhấn “Áp dụng” trong cart/order
  - Hiển thị số tiền giảm giá, thông tin voucher đã áp dụng

---

## 3. Ghi chú về phân quyền, validate, UI mapping
- **ADMIN:** Có thể thao tác với mọi voucher, tạo cho toàn hệ thống hoặc shop bất kỳ.
- **SELLER:** Chỉ thao tác với voucher của shop mình.
- **CLIENT:** Chỉ lấy/áp dụng voucher khả dụng, không được tạo/sửa/xóa.
- **GUEST:** Chỉ lấy voucher khả dụng, không được áp dụng.
- **Validate:** Kiểm tra điều kiện, số lượt dùng, trạng thái, thời gian, minOrderValue, appliesTo, shopId, sản phẩm, ...
- **UI mapping:**
  - Trang tạo voucher: POST /discounts
  - Danh sách voucher: GET /discounts
  - Popup chọn voucher: GET /discounts/available
  - Áp dụng voucher: POST /discounts/verify
  - Xem chi tiết voucher: GET /discounts/:id
  - Sửa voucher: PUT /discounts/:id
  - Xóa voucher: DELETE /discounts/:id

---

**Nếu cần bổ sung API hoặc logic nghiệp vụ đặc biệt, hãy liên hệ backend để được hỗ trợ!**
