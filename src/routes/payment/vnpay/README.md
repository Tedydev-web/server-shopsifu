# VNPay Payment Integration

Module tích hợp cổng thanh toán VNPay cho hệ thống Shopsifu với đầy đủ tính năng theo thư viện `vnpay`.

## Các Endpoint

### 1. Lấy danh sách ngân hàng

**GET** `/payment/vnpay/bank-list`

Lấy danh sách các ngân hàng hỗ trợ thanh toán VNPay.

**Response:**
```json
{
  "banks": [
    {
      "bankCode": "NCB",
      "bankName": "Ngân hàng NCB",
      "bankLogo": "https://example.com/logo.png",
      "bankType": 1,
      "displayOrder": 1
    }
  ]
}
```

### 2. Tạo URL thanh toán

**POST** `/payment/vnpay/create-payment`

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
  "orderType": "other",
  "createDate": 20231201120000,
  "expireDate": 20231202120000,
  "ipAddr": "127.0.0.1"
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

**GET** `/payment/vnpay/verify-return`

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
    "payDate": "20170829153052",
    "cardType": "ATM"
  }
}
```

### 4. Xác thực IPN Call

**POST** `/payment/vnpay/verify-ipn`

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
    "payDate": "20170829153052",
    "cardType": "ATM"
  }
}
```

### 5. Truy vấn kết quả thanh toán

**POST** `/payment/vnpay/query-dr`

Truy vấn kết quả thanh toán của giao dịch từ hệ thống VNPay.

**Request Body:**
```json
{
  "orderId": "ORDER_12345",
  "orderInfo": "Thanh toan don hang 12345",
  "requestId": "REQUEST_12345",
  "transactionDate": 20231201120000,
  "transactionNo": 20170829153052,
  "ipAddr": "127.0.0.1",
  "createDate": 20231201120000
}
```

**Response:**
```json
{
  "isSuccess": true,
  "isVerified": true,
  "message": "Truy vấn thành công",
  "data": {
    "orderId": "ORDER_12345",
    "amount": "100000",
    "responseCode": "00",
    "command": "querydr",
    "payDate": "20170829153052",
    "orderInfo": "Thanh toan don hang 12345",
    "transactionStatus": "00",
    "bankCode": "NCB",
    "responseId": "RESPONSE_12345",
    "message": "Giao dịch thành công",
    "transactionType": "01",
    "promotionCode": "PROMO123",
    "promotionAmount": 5000,
    "transactionNo": "20170829153052"
  }
}
```

### 6. Hoàn tiền

**POST** `/payment/vnpay/refund`

Thực hiện hoàn tiền cho giao dịch VNPay.

**Request Body:**
```json
{
  "orderId": "ORDER_12345",
  "orderInfo": "Hoan tien don hang 12345",
  "amount": 100000,
  "requestId": "REFUND_12345",
  "transactionDate": 20231201120000,
  "transactionNo": 20170829153052,
  "transactionType": "02",
  "createBy": "admin",
  "createDate": 20231201120000,
  "ipAddr": "127.0.0.1",
  "locale": "vn"
}
```

**Response:**
```json
{
  "isSuccess": true,
  "isVerified": true,
  "message": "Hoàn tiền thành công",
  "data": {
    "orderId": "ORDER_12345",
    "amount": "100000",
    "responseCode": "00",
    "message": "Hoàn tiền thành công",
    "bankCode": "NCB",
    "payDate": "20170829153052",
    "transactionNo": "20170829153052",
    "transactionType": "02",
    "transactionStatus": "00",
    "responseId": "REFUND_RESPONSE_12345",
    "command": "refund",
    "tmnCode": "E12E8KYJ",
    "orderInfo": "Hoan tien don hang 12345"
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

## Các loại giao dịch

### ProductCode (Loại sản phẩm)
- `100000`: Thực phẩm - Tiêu dùng
- `110000`: Điện thoại - Máy tính bảng
- `120000`: Điện máy
- `130000`: Máy tính - Thiết bị văn phòng
- `140000`: Điện tử - Âm thanh
- `150000`: Sách - Báo - Tạp chí
- `160000`: Thể thao - Dã ngoại
- `170000`: Khách sạn - Du lịch
- `180000`: Ẩm thực
- `190000`: Giải trí - Đào tạo
- `200000`: Thời trang
- `210000`: Sức khỏe - Làm đẹp
- `220000`: Mẹ và bé
- `230000`: Đồ dùng nhà bếp
- `240000`: Xe cộ
- `250000`: Thanh toán
- `250007`: Vé máy bay
- `260000`: Mã thẻ
- `270000`: Dược phẩm - Dịch vụ y tế
- `other`: Khác

### VnpTransactionType (Loại giao dịch)
- `01`: Giao dịch thanh toán
- `02`: Giao dịch hoàn trả toàn phần
- `03`: Giao dịch hoàn trả một phần

### RefundTransactionType (Loại hoàn tiền)
- `02`: Hoàn trả toàn phần
- `03`: Hoàn trả một phần

### VnpCardType (Loại thẻ)
- `ATM`: Thẻ ATM
- `QRCODE`: QR Code

### VnpLocale (Ngôn ngữ)
- `vn`: Tiếng Việt
- `en`: Tiếng Anh

### VnpCurrCode (Đơn vị tiền tệ)
- `VND`: Đồng Việt Nam

## Lưu ý

1. **Test Mode**: Hiện tại đang sử dụng sandbox của VNPay để test
2. **IP Address**: Mặc định sử dụng `127.0.0.1`, có thể cập nhật để lấy từ request
3. **Validation**: Tất cả input đều được validate bằng Zod schema
4. **Error Handling**: Các lỗi được xử lý và trả về message rõ ràng
5. **Response Format**: Tuân thủ chuẩn response format của hệ thống
6. **Logging**: Tất cả các operation đều có logging để debug
7. **Type Safety**: Sử dụng TypeScript với full type support
8. **Hash Verification**: Tất cả các giao dịch đều được verify hash để đảm bảo an toàn

## Tài liệu tham khảo

- [VNPay Documentation](https://sandbox.vnpayment.vn/apis/docs/thanh-toan-pay/pay.html)
- [nestjs-vnpay](https://github.com/lehuygiang28/nestjs-vnpay)
- [vnpay package](https://www.npmjs.com/package/vnpay)
- [VNPay API Reference](https://vnpay.js.org/)
