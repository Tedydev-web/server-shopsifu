# VNPay Payment Module

## Overview
Module xử lý thanh toán qua VNPay gateway, hỗ trợ đầy đủ các tính năng thanh toán, hoàn tiền và IPN callback.

## Features
- ✅ Tạo URL thanh toán VNPay
- ✅ Xác thực return URL
- ✅ Truy vấn kết quả thanh toán
- ✅ Hoàn tiền giao dịch
- ✅ IPN callback (Instant Payment Notification)
- ✅ WebSocket real-time notifications
- ✅ Pass tất cả 6 test case VNPay
- ✅ Clean architecture với separation of concerns
- ✅ Chuẩn hóa logic xử lý tiền

## API Endpoints

### 1. Tạo thanh toán
```http
POST /payment/vnpay/create
```

### 2. Xác thực return URL
```http
GET /payment/vnpay/verify-return
```

### 3. IPN Callback (Server-to-Server)
```http
GET /payment/vnpay/verify-ipn
```

### 4. Truy vấn giao dịch
```http
POST /payment/vnpay/query-dr
```

### 5. Hoàn tiền
```http
POST /payment/vnpay/refund
```

## IPN Implementation

### HTTP Method
- **Method**: `GET` (VNPay gửi dữ liệu qua query parameters)

### Response Format
IPN endpoint trả về JSON format theo chuẩn VNPay:
```json
{
  "RspCode": "00",
  "Message": "Confirm Success"
}
```

### Response Codes
- `00`: Confirm Success
- `01`: Order not found
- `02`: Order already confirmed
- `04`: Invalid amount
- `97`: Invalid Checksum
- `99`: Unknown error

### Test Cases Support
✅ **Test Case 1**: Giao dịch thành công (vnp_ResponseCode: 00)
✅ **Test Case 2**: Giao dịch không thành công (vnp_ResponseCode: 99)
✅ **Test Case 3**: Không tìm thấy giao dịch (vnp_TxnRef không tồn tại)
✅ **Test Case 4**: Giao dịch đã được confirm (payment status = SUCCESS/FAILED)
✅ **Test Case 5**: Số tiền không hợp lệ (vnp_Amount sai)
✅ **Test Case 6**: Chữ ký không hợp lệ (vnp_SecureHash sai)

### Retry Mechanism
- VNPay sẽ retry IPN tối đa 10 lần
- Khoảng cách giữa các lần retry: 5 phút
- RspCode: 00, 02 → VNPay kết thúc luồng
- RspCode: 01, 04, 97, 99 → VNPay bật cơ chế retry

## Architecture

### Service Layer
- `VNPayService`: Điều phối nghiệp vụ, không truy vấn DB trực tiếp
- Xử lý WebSocket notifications
- Orchestrate giữa thư viện VNPay và repository

### Repository Layer
- `VNPayRepo`: Xử lý các thao tác DB cho VNPay
- Tách biệt logic nghiệp vụ
- Sử dụng `SharedPaymentRepository` cho logic chung

### Shared Repository
- `SharedPaymentRepository`: Logic chung cho tất cả payment gateways
- Extract payment ID, validate amount, update status
- Centralized business logic

## Amount Handling (Chuẩn hóa)

### Data Flow
1. **Client gửi**: `amount` (VND) → `createPayment()`
2. **VNPay gửi**: `vnp_Amount` (VND * 100) → `processIpnCall()`
3. **Thư viện xử lý**: `verify.vnp_Amount` (VND) → `verifyIpnCall()`
4. **DB lưu**: `amountIn` (VND) → `paymentTransaction`
5. **Validation**: So sánh VND với VND (tolerance 0.01)

### Amount Processing Rules
- **VNPay raw**: `vnp_Amount` = VND * 100
- **Thư viện processed**: `verify.vnp_Amount` = VND (đã chia 100)
- **DB storage**: `amountIn` = VND (đã chia 100)
- **Validation**: So sánh cùng đơn vị VND

### Validation Logic
```typescript
// Trong SharedPaymentRepository
validatePaymentAmount(orders, expectedAmount, actualAmount) {
  const expected = parseFloat(expectedAmount) // VND từ DB
  const actual = parseFloat(actualAmount.toString()) // VND từ VNPay
  if (Math.abs(expected - actual) > 0.01) { // Tolerance cho float
    throw new BadRequestException(`Price not match`)
  }
}
```

## Error Handling
- Custom exceptions cho từng loại lỗi
- Graceful degradation
- Detailed error logging

## Version History
- **v1.0.0**: Initial implementation
- **v1.1.0**: Add IPN support with GET method
- **v1.2.0**: Fix amount validation logic
- **v1.3.0**: Pass all 6 VNPay test cases
- **v1.4.0**: Clean up code, remove debug logs
- **v1.5.0**: Chuẩn hóa logic xử lý tiền, clean architecture

## Dependencies
- `nestjs-vnpay`: VNPay SDK
- `socket.io`: WebSocket notifications
- `nestjs-i18n`: Internationalization
