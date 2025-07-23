# Test Implementation của Discount Integration

## 🎯 **Các thành phần đã được implement**

### 1. **API Endpoints mới**
```
POST /discounts/available-for-checkout
- Body: { cartItemIds: string[] }
- Response: Danh sách mã giảm giá khả dụng

POST /orders/calculate
- Body: { cartItemIds: string[], discountCodes?: string[] }
- Response: Chi tiết giá đã tính toán với discount
```

### 2. **Cập nhật API tạo đơn hàng**
```
POST /orders
- Body: Thêm trường discountCodes vào mỗi đơn hàng
[{
  shopId: string,
  cartItemIds: string[],
  receiver: {...},
  discountCodes?: string[]  // ← Trường mới
}]
```

### 3. **Luồng xử lý hoàn chỉnh**

#### **Bước 1: Lấy mã giảm giá khả dụng**
```javascript
// Frontend gọi khi vào trang thanh toán
const response = await fetch('/discounts/available-for-checkout', {
  method: 'POST',
  body: JSON.stringify({ cartItemIds: ["cart-id-1", "cart-id-2"] })
});
// Response: Danh sách mã giảm giá có thể áp dụng
```

#### **Bước 2: Tính toán giá khi chọn mã**
```javascript
// Frontend gọi khi user chọn/thay đổi mã giảm giá
const response = await fetch('/orders/calculate', {
  method: 'POST',
  body: JSON.stringify({
    cartItemIds: ["cart-id-1", "cart-id-2"],
    discountCodes: ["S-STUDENT", "S-VIP"]
  })
});
// Response: { subTotal, discounts: [...], grandTotal }
```

#### **Bước 3: Tạo đơn hàng với discount**
```javascript
// Frontend gọi khi user bấm "Thanh toán"
const response = await fetch('/orders', {
  method: 'POST',
  body: JSON.stringify([{
    shopId: "shop-id",
    cartItemIds: ["cart-id-1", "cart-id-2"],
    receiver: { name: "...", phone: "...", address: "..." },
    discountCodes: ["S-STUDENT", "S-VIP"]  // ← Trường mới
  }])
});
```

### 4. **Database Changes**

#### **DiscountSnapshot được tạo khi có discount:**
```sql
-- Mỗi mã giảm giá được "đóng băng" thông tin tại thời điểm đặt hàng
INSERT INTO "DiscountSnapshot" (
  name, description, type, value, code,
  discountAmount,  -- ← Số tiền thực tế đã giảm
  orderId, discountId
) VALUES (...)
```

#### **Payment verification cập nhật:**
```typescript
// Tính tổng giá = Giá sản phẩm - Giảm giá
const productTotal = order.items.reduce((sum, item) =>
  sum + item.skuPrice * item.quantity, 0);

const discountTotal = order.discountSnapshots.reduce((sum, discount) =>
  sum + discount.discountAmount, 0);

const finalTotal = productTotal - discountTotal;
```

## 🔧 **Cách test thủ công**

### **Test Case 1: Không có discount**
1. Thêm sản phẩm vào giỏ hàng
2. Gọi `POST /orders/calculate` không có discountCodes
3. Kiểm tra: grandTotal = subTotal
4. Tạo đơn hàng → Không có DiscountSnapshot nào được tạo

### **Test Case 2: Có discount hợp lệ**
1. Tạo discount code trong database
2. Gọi `POST /discounts/available-for-checkout`
3. Kiểm tra: API trả về discount vừa tạo
4. Gọi `POST /orders/calculate` với discount code
5. Kiểm tra: grandTotal = subTotal - discount amount
6. Tạo đơn hàng với discount code
7. Kiểm tra: DiscountSnapshot được tạo với đúng thông tin

### **Test Case 3: Thanh toán với discount**
1. Tạo đơn hàng có discount
2. Simulate webhook từ SePay
3. Kiểm tra: Hệ thống tính đúng tổng tiền (đã trừ discount)
4. Kiểm tra: Thanh toán thành công khi số tiền khớp

## 🚀 **Các tính năng đã hoàn thành**

✅ **Snapshot Pattern**: DiscountSnapshot lưu giữ thông tin discount tại thời điểm đặt hàng
✅ **Multi-discount**: Hỗ trợ áp dụng nhiều mã giảm giá cùng lúc
✅ **Discount validation**: Kiểm tra điều kiện áp dụng (thời gian, số lượng, giá trị đơn hàng)
✅ **Usage tracking**: Cập nhật số lần sử dụng discount
✅ **Payment verification**: Xác thực thanh toán với giá đã trừ discount
✅ **Transaction safety**: Tất cả thao tác trong transaction đảm bảo tính toàn vẹn

## 🔄 **Luồng hoàn chỉnh**

```
User adds products to cart
       ↓
Enter checkout page
       ↓
Call /discounts/available-for-checkout
       ↓
Display discount options
       ↓
User selects discount codes
       ↓
Call /orders/calculate (real-time price update)
       ↓
User confirms checkout
       ↓
Call /orders with discountCodes
       ↓
Create Order + ProductSKUSnapshot + DiscountSnapshot
       ↓
Redirect to payment gateway
       ↓
Payment webhook verifies price (including discount)
       ↓
Order status updated to PENDING_PICKUP
```

Toàn bộ discount integration đã được implement hoàn chỉnh theo đúng thiết kế đã thảo luận!
