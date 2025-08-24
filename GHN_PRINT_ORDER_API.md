# 🖨️ GHN Print Order API

## Tổng quan

Endpoint này cho phép tạo token và URLs để in đơn hàng GHN với các kích thước khác nhau (A5, 80x80, 50x72).

## 📋 API Endpoint

```
POST /shipping/ghn/print-order
```

## 🔐 Authentication

Yêu cầu Bearer token trong header:
```
Authorization: Bearer <access_token>
```

## 📝 Request Body

```json
{
  "orderCodes": ["GA99W4RREB", "GA99W4RREB2"]
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `orderCodes` | `string[]` | ✅ | Mảng các mã đơn hàng GHN cần in |

## 📤 Response

### Success Response (200)

```json
{
  "message": "Tạo token in đơn hàng thành công",
  "data": {
    "token": "e27db030-a1bf-11ea-b421-6a186c15e40e",
    "printUrls": {
      "a5": "https://online-gateway.ghn.vn/a5/public-api/printA5?token=e27db030-a1bf-11ea-b421-6a186c15e40e",
      "80x80": "https://online-gateway.ghn.vn/a5/public-api/print80x80?token=e27db030-a1bf-11ea-b421-6a186c15e40e",
      "50x72": "https://online-gateway.ghn.vn/a5/public-api/print52x70?token=e27db030-a1bf-11ea-b421-6a186c15e40e"
    }
  }
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `message` | `string` | Thông báo kết quả |
| `data.token` | `string` | Token để truy cập các URL in |
| `data.printUrls.a5` | `string` | URL in khổ A5 |
| `data.printUrls.80x80` | `string` | URL in khổ 80x80 |
| `data.printUrls.50x72` | `string` | URL in khổ 50x72 |

## 🚀 Cách sử dụng

### 1. Tạo token in đơn hàng

```bash
curl -X POST "http://localhost:3000/shipping/ghn/print-order" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"orderCodes": ["GA99W4RREB"]}'
```

### 2. Sử dụng URLs để in

Sau khi có token, bạn có thể:

- **In khổ A5**: Mở URL `data.printUrls.a5` trong trình duyệt
- **In khổ 80x80**: Mở URL `data.printUrls.80x80` trong trình duyệt
- **In khổ 50x72**: Mở URL `data.printUrls.50x72` trong trình duyệt

### 3. Tự động in

```javascript
// Tự động mở cửa sổ in
const printWindow = window.open(printUrl, '_blank');
if (printWindow) {
  printWindow.print();
}
```

## ⚠️ Lưu ý quan trọng

1. **Token có thời hạn**: Token chỉ có hiệu lực trong 30 phút
2. **Order codes phải tồn tại**: Các mã đơn hàng phải đã được tạo trong GHN
3. **Quyền truy cập**: User phải có quyền truy cập vào các đơn hàng này
4. **Rate limiting**: GHN có thể giới hạn số lượng request

## 🔧 Cấu hình

### Environment Variables

```env
GHN_TOKEN=your_ghn_token_here
GHN_HOST=https://online-gateway.ghn.vn
```

### GHN API Endpoints

- **Production**: `https://online-gateway.ghn.vn`
- **Test**: `https://dev-online-gateway.ghn.vn`

## 📊 Error Handling

### Common Errors

| HTTP Status | Error Message | Description |
|-------------|---------------|-------------|
| `400` | `Order codes are required` | Thiếu mã đơn hàng |
| `400` | `Invalid order code` | Mã đơn hàng không hợp lệ |
| `500` | `GHN API error: ...` | Lỗi từ GHN API |
| `500` | `Failed to generate print token from GHN` | Không thể tạo token |

## 🧪 Testing

Sử dụng script test có sẵn:

```bash
# Cập nhật ACCESS_TOKEN và ORDER_CODES trong script
chmod +x test-print-order.sh
./test-print-order.sh
```

## 📚 Tài liệu tham khảo

- [GHN Print Order API Documentation](https://api.ghn.vn/home/docs/detail?id=67)
- [GHN API Homepage](https://api.ghn.vn/)

## 🔄 Workflow

```
1. User gọi API với order codes
2. Hệ thống validate dữ liệu
3. Gọi GHN API để tạo token
4. Tạo URLs in với các kích thước khác nhau
5. Trả về token và URLs cho user
6. User sử dụng URLs để in đơn hàng
```

## 💡 Best Practices

1. **Cache token**: Lưu trữ token để tái sử dụng trong 30 phút
2. **Batch printing**: Gộp nhiều đơn hàng vào một request
3. **Error retry**: Implement retry logic khi GHN API fail
4. **Logging**: Log tất cả các request và response để debug
