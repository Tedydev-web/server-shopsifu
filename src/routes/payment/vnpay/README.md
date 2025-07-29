# VNPay Payment Integration

Module tích hợp cổng thanh toán VNPay cho hệ thống Shopsifu.

## Các Endpoint

### 1. Lấy danh sách ngân hàng

**GET** `/vnpay/bank-list`

Lấy danh sách các ngân hàng hỗ trợ thanh toán VNPay.

**Response:**
```json
{
  "banks": [
    {
      "bankCode": "NCB",
      "bankName": "Ngân hàng NCB",
      "bankLogo": "https://example.com/logo.png"
    }
  ]
}
```

### 2. Tạo URL thanh toán

**POST** `/vnpay/create-payment`

Tạo URL thanh toán VNPay cho đơn hàng.

**Request Body:**
```json
{
  "amount": 100000,
  "orderInfo": "Thanh toan don hang 12345",
  "orderId": "ORDER_12345",
  "returnUrl": "https://your-domain.com/payment/return",
  "ipnUrl": "https://your-domain.com/payment/ipn",
  "locale": "vn",
  "currency": "VND",
  "bankCode": "NCB",
  "language": "vn",
  "customerEmail": "customer@example.com",
  "customerPhone": "0123456789",
  "customerAddress": "123 Nguyen Van A, Ha Noi",
  "customerName": "Nguyen Van A"
}
```

**Response:**
```json
{
  "paymentUrl": "https://sandbox.vnpayment.vn/paymentv2/vpcpay.html?vnp_Amount=100000&...",
  "orderId": "ORDER_12345",
  "amount": 100000,
  "orderInfo": "Thanh toan don hang 12345"
}
```

### 3. Xác thực URL trả về

**GET** `/vnpay/verify-return`

Xác thực dữ liệu trả về từ VNPay khi khách hàng hoàn tất thanh toán.

**Query Parameters:**
```
?vnp_Amount=100000&vnp_BankCode=NCB&vnp_OrderInfo=Thanh toan don hang 12345&...
```

**Response:**
```json
{
  "isSuccess": true,
  "isVerified": true,
  "message": "Giao dịch thành công",
  "data": {
    "orderId": "ORDER_12345",
    "amount": "100000",
    "transactionNo": "20170829153052",
    "responseCode": "00",
    "transactionStatus": "00",
    "bankCode": "NCB",
    "bankTranNo": "NCB20170829152730",
    "payDate": "20170829153052"
  }
}
```

### 4. Xác thực IPN Call

**POST** `/vnpay/verify-ipn`

Xác thực IPN (Instant Payment Notification) call từ VNPay.

**Request Body:**
```json
{
  "vnp_Amount": "100000",
  "vnp_BankCode": "NCB",
  "vnp_OrderInfo": "Thanh toan don hang 12345",
  "vnp_PayDate": "20170829153052",
  "vnp_ResponseCode": "00",
  "vnp_TmnCode": "E12E8KYJ",
  "vnp_TransactionNo": "20170829153052",
  "vnp_TransactionStatus": "00",
  "vnp_TxnRef": "ORDER_12345",
  "vnp_SecureHash": "hash_string"
}
```

**Response:**
```json
{
  "isSuccess": true,
  "isVerified": true,
  "message": "Giao dịch thành công",
  "data": {
    "orderId": "ORDER_12345",
    "amount": "100000",
    "transactionNo": "20170829153052",
    "responseCode": "00",
    "transactionStatus": "00",
    "bankCode": "NCB",
    "bankTranNo": "NCB20170829152730",
    "payDate": "20170829153052"
  }
}
```

## Cấu hình

Module VNPay được cấu hình trong `vnpay.module.ts` với các thông số:

- **TMN Code**: `E12E8KYJ`
- **Secure Secret**: `VMZQECLOHDPXFBHLHMHYDLYIANSIHGQM`
- **VNPay Host**: `https://sandbox.vnpayment.vn` (test mode)
- **Hash Algorithm**: `SHA512`
- **Test Mode**: `true`

## Lưu ý

1. **Test Mode**: Hiện tại đang sử dụng sandbox của VNPay để test
2. **IP Address**: Mặc định sử dụng `127.0.0.1`, có thể cập nhật để lấy từ request
3. **Validation**: Tất cả input đều được validate bằng Zod schema
4. **Error Handling**: Các lỗi được xử lý và trả về message rõ ràng
5. **Response Format**: Tuân thủ chuẩn response format của hệ thống

## Tài liệu tham khảo

- [VNPay Documentation](https://sandbox.vnpayment.vn/apis/docs/thanh-toan-pay/pay.html)
- [nestjs-vnpay](https://github.com/lehuygiang28/nestjs-vnpay)
- [vnpay package](https://www.npmjs.com/package/vnpay)
