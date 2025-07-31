# VNPay Payment Integration - Hướng Dẫn Chi Tiết

**Version:** 1.2.1
**Last Updated:** 2025-07-31
**Author:** Development Team

Module tích hợp cổng thanh toán VNPay cho hệ thống Shopsifu với đầy đủ tính năng theo thư viện `vnpay`.

## 📋 Mục Lục

1. [Cấu hình và Setup](#cấu-hình-và-setup)
2. [Flow Thanh Toán Hoàn Chỉnh](#flow-thanh-toán-hoàn-chỉnh)
3. [API Endpoints Chi Tiết](#api-endpoints-chi-tiết)
4. [Client Integration](#client-integration)
5. [Webhook và IPN](#webhook-và-ipn)
6. [Error Handling](#error-handling)
7. [Testing](#testing)

## 🔧 Cấu Hình và Setup

### Environment Variables
```env
# VNPay Configuration
VNPAY_TMN_CODE=E12E8KYJ
VNPAY_SECURE_SECRET=VMZQECLOHDPXFBHLHMHYDLYIANSIHGQM
VNPAY_HOST=https://sandbox.vnpayment.vn
NODE_ENV=development
```

### Module Configuration
```typescript
// vnpay.module.ts
@Module({
  imports: [
    VnpayModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        tmnCode: configService.getOrThrow<string>('payment.vnpay.tmnCode'),
        secureSecret: configService.getOrThrow<string>('payment.vnpay.secureSecret'),
        vnpayHost: process.env.NODE_ENV === 'production'
          ? 'https://pay.vnpay.vn'
          : 'https://sandbox.vnpayment.vn',
        testMode: process.env.NODE_ENV !== 'production',
        hashAlgorithm: HashAlgorithm.SHA512,
        enableLog: process.env.NODE_ENV !== 'production',
        loggerFn: ignoreLogger
      }),
      inject: [ConfigService]
    })
  ],
  providers: [VNPayService, VNPayRepo, PaymentProducer],
  controllers: [VNPayController]
})
```

## 🔄 Flow Thanh Toán Hoàn Chỉnh

### 1. Client Tạo Đơn Hàng
```javascript
// Client tạo đơn hàng với payment gateway = 'vnpay'
const orderData = {
  items: [
    { productId: 'prod_123', quantity: 2, skuId: 'sku_456' }
  ],
  paymentGateway: 'vnpay', // Quan trọng: chỉ định gateway
  shippingAddress: {
    address: '123 Đường ABC',
    city: 'Hà Nội',
    phone: '0123456789'
  }
}

const response = await fetch('/api/orders', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(orderData)
})

// Response từ server
{
  "statusCode": 201,
  "message": "Tạo đơn hàng thành công",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "data": {
    "orderId": "ORDER_12345",
    "paymentUrl": "https://sandbox.vnpayment.vn/paymentv2/vpcpay.html?vnp_Amount=100000&...",
    "amount": 100000,
    "paymentGateway": "vnpay"
  }
}
```

### 2. Client Redirect đến VNPay
```javascript
// Client redirect user đến VNPay
window.location.href = response.data.paymentUrl
```

### 3. User Thanh Toán trên VNPay
- User nhập thông tin thẻ/ngân hàng
- VNPay xử lý thanh toán
- VNPay redirect về `returnUrl` với kết quả

### 4. VNPay Redirect về Website
```
https://your-domain.com/payment/return?vnp_Amount=100000&vnp_BankCode=NCB&vnp_OrderInfo=Thanh%20toan%20don%20hang%2012345&vnp_PayDate=20240115103000&vnp_ResponseCode=00&vnp_TmnCode=E12E8KYJ&vnp_TransactionNo=20240115103000&vnp_TransactionStatus=00&vnp_TxnRef=ORDER_12345&vnp_SecureHash=hash_string
```

### 5. Client Xử Lý Return URL
```javascript
// Client gọi API verify return
const urlParams = new URLSearchParams(window.location.search)
const verifyData = Object.fromEntries(urlParams.entries())

const verifyResponse = await fetch('/api/payment/vnpay/verify-return', {
  method: 'GET',
  headers: { 'Content-Type': 'application/json' }
})

// Response
{
  "statusCode": 200,
  "message": "Xác thực thành công",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "data": {
    "isSuccess": true,
    "isVerified": true,
    "message": "Giao dịch thành công",
    "vnp_Amount": 100000,
    "vnp_TxnRef": "ORDER_12345",
    "vnp_TransactionNo": "20240115103000",
    "vnp_ResponseCode": "00",
    "vnp_TransactionStatus": "00"
  }
}
```

## 📡 API Endpoints Chi Tiết

### 1. Lấy Danh Sách Ngân Hàng

**Endpoint:** `GET /api/payment/vnpay/bank-list`

**Request:**
```http
GET /api/payment/vnpay/bank-list
Content-Type: application/json
```

**Response:**
```json
{
  "statusCode": 200,
  "message": "Lấy danh sách ngân hàng thành công",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "data": {
    "banks": [
      {
        "bankCode": "NCB",
        "bankName": "Ngân hàng NCB",
        "bankLogo": "https://example.com/logo.png",
        "bankType": 1,
        "displayOrder": 1
      },
      {
        "bankCode": "VCB",
        "bankName": "Vietcombank",
        "bankLogo": "https://example.com/vcb.png",
        "bankType": 1,
        "displayOrder": 2
      }
    ]
  }
}
```

### 2. Tạo URL Thanh Toán

**Endpoint:** `POST /api/payment/vnpay/create-payment`

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
  "ipAddr": "127.0.0.1"
}
```

**Field Descriptions:**
- `amount` (number): Số tiền thanh toán (VND)
- `orderInfo` (string): Nội dung thanh toán
- `orderId` (string): Mã đơn hàng
- `returnUrl` (string): URL redirect sau khi thanh toán
- `ipnUrl` (string, optional): URL nhận IPN từ VNPay
- `locale` (string): Ngôn ngữ ("vn" hoặc "en")
- `currency` (string): Đơn vị tiền tệ ("VND")
- `bankCode` (string, optional): Mã ngân hàng cụ thể
- `orderType` (string): Loại đơn hàng
- `ipAddr` (string): IP của khách hàng

**Response:**
```json
{
  "statusCode": 200,
  "message": "Tạo URL thanh toán thành công",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "data": {
    "paymentUrl": "https://sandbox.vnpayment.vn/paymentv2/vpcpay.html?vnp_Amount=100000&vnp_OrderInfo=Thanh%20toan%20don%20hang%2012345&vnp_TxnRef=ORDER_12345&vnp_ReturnUrl=https%3A//your-domain.com/payment/return&vnp_IpAddr=127.0.0.1&vnp_Locale=vn&vnp_CurrCode=VND&vnp_OrderType=other&vnp_SecureHash=hash_string",
    "orderId": "ORDER_12345",
    "amount": 100000,
    "orderInfo": "Thanh toan don hang 12345"
  }
}
```

### 3. Xác Thực URL Trả Về

**Endpoint:** `GET /api/payment/vnpay/verify-return`

**Query Parameters:**
```
?vnp_Amount=100000&vnp_BankCode=NCB&vnp_OrderInfo=Thanh%20toan%20don%20hang%2012345&vnp_PayDate=20240115103000&vnp_ResponseCode=00&vnp_TmnCode=E12E8KYJ&vnp_TransactionNo=20240115103000&vnp_TransactionStatus=00&vnp_TxnRef=ORDER_12345&vnp_SecureHash=hash_string
```

**Query Parameter Descriptions:**
- `vnp_Amount`: Số tiền thanh toán
- `vnp_BankCode`: Mã ngân hàng
- `vnp_OrderInfo`: Nội dung đơn hàng
- `vnp_PayDate`: Ngày thanh toán (yyyyMMddHHmmss)
- `vnp_ResponseCode`: Mã phản hồi (00 = thành công)
- `vnp_TmnCode`: Mã merchant
- `vnp_TransactionNo`: Mã giao dịch VNPay
- `vnp_TransactionStatus`: Trạng thái giao dịch
- `vnp_TxnRef`: Mã đơn hàng
- `vnp_SecureHash`: Chữ ký bảo mật

**Response:**
```json
{
  "statusCode": 200,
  "message": "Xác thực URL trả về thành công",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "data": {
    "isSuccess": true,
    "isVerified": true,
    "message": "Giao dịch thành công",
    "vnp_Amount": 100000,
    "vnp_TxnRef": "ORDER_12345",
    "vnp_TransactionNo": "20240115103000",
    "vnp_ResponseCode": "00",
    "vnp_TransactionStatus": "00"
  }
}
```

### 4. Xác Thực IPN Call

**Endpoint:** `GET /api/payment/vnpay/verify-ipn`

**Query Parameters:**
```
?vnp_Amount=100000&vnp_BankCode=NCB&vnp_OrderInfo=Thanh%20toan%20don%20hang%2012345&vnp_PayDate=20240115103000&vnp_ResponseCode=00&vnp_TmnCode=E12E8KYJ&vnp_TransactionNo=20240115103000&vnp_TransactionStatus=00&vnp_TxnRef=ORDER_12345&vnp_SecureHash=hash_string
```

**Query Parameter Descriptions:**
- `vnp_Amount`: Số tiền thanh toán
- `vnp_BankCode`: Mã ngân hàng
- `vnp_OrderInfo`: Nội dung đơn hàng
- `vnp_PayDate`: Ngày thanh toán (yyyyMMddHHmmss)
- `vnp_ResponseCode`: Mã phản hồi (00 = thành công)
- `vnp_TmnCode`: Mã merchant
- `vnp_TransactionNo`: Mã giao dịch VNPay
- `vnp_TransactionStatus`: Trạng thái giao dịch
- `vnp_TxnRef`: Mã đơn hàng
- `vnp_SecureHash`: Chữ ký bảo mật

**Response (JSON Format):**
```json
{
  "RspCode": "00",
  "Message": "Confirm Success"
}
```

**Response Code Descriptions:**
- `00`, `02`: Thành công (VNPay kết thúc luồng)
- `01`, `04`, `97`, `99`: Lỗi (VNPay retry)

**Lưu ý quan trọng:**
- IPN call được VNPay gửi qua **GET request với query parameters**
- Response phải là **JSON format** với `RspCode` và `Message`
- VNPay sẽ retry nếu nhận được RspCode lỗi (tối đa 10 lần, mỗi 5 phút)

### 5. Truy Vấn Kết Quả Thanh Toán

**Endpoint:** `POST /api/payment/vnpay/query-dr`

**Request Body:**
```json
{
  "orderId": "ORDER_12345",
  "orderInfo": "Thanh toan don hang 12345",
  "requestId": "REQUEST_12345",
  "transactionDate": 20240115103000,
  "transactionNo": 20240115103000,
  "ipAddr": "127.0.0.1",
  "createDate": 20240115103000
}
```

**Field Descriptions:**
- `orderId` (string): Mã đơn hàng
- `orderInfo` (string): Nội dung đơn hàng
- `requestId` (string): Mã yêu cầu truy vấn
- `transactionDate` (number): Ngày giao dịch (yyyyMMddHHmmss)
- `transactionNo` (number): Mã giao dịch VNPay
- `ipAddr` (string): IP của client
- `createDate` (number): Ngày tạo yêu cầu (yyyyMMddHHmmss)

**Response:**
```json
{
  "statusCode": 200,
  "message": "Truy vấn kết quả thanh toán thành công",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "data": {
    "isSuccess": true,
    "isVerified": true,
    "message": "Truy vấn thành công",
    "vnp_Amount": 100000,
    "vnp_TxnRef": "ORDER_12345",
    "vnp_TransactionNo": "20240115103000",
    "vnp_ResponseCode": "00",
    "vnp_TransactionStatus": "00"
  }
}
```

### 6. Hoàn Tiền

**Endpoint:** `POST /api/payment/vnpay/refund`

**Request Body:**
```json
{
  "orderId": "ORDER_12345",
  "orderInfo": "Hoan tien don hang 12345",
  "amount": 100000,
  "requestId": "REFUND_12345",
  "transactionNo": 20240115103000,
  "ipAddr": "127.0.0.1",
  "createBy": "admin"
}
```

**Field Descriptions:**
- `orderId` (string): Mã đơn hàng gốc
- `orderInfo` (string): Nội dung hoàn tiền
- `amount` (number): Số tiền hoàn
- `requestId` (string): Mã yêu cầu hoàn tiền
- `transactionNo` (number): Mã giao dịch gốc
- `ipAddr` (string): IP của client
- `createBy` (string): Người tạo yêu cầu hoàn tiền

**Response:**
```json
{
  "statusCode": 200,
  "message": "Hoàn tiền thành công",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "data": {
    "isSuccess": true,
    "isVerified": true,
    "message": "Hoàn tiền thành công",
    "vnp_Amount": 100000,
    "vnp_TxnRef": "ORDER_12345",
    "vnp_TransactionNo": "20240115103000",
    "vnp_ResponseCode": "00",
    "vnp_TransactionStatus": "00"
  }
}
```

## 💻 Client Integration

### 1. Frontend JavaScript Example

```javascript
class VNPayPayment {
  constructor(baseUrl = 'https://your-api-domain.com') {
    this.baseUrl = baseUrl
  }

  // Tạo đơn hàng với VNPay
  async createOrder(orderData) {
    try {
      const response = await fetch(`${this.baseUrl}/api/orders`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getToken()}`
        },
        body: JSON.stringify({
          ...orderData,
          paymentGateway: 'vnpay'
        })
      })

      const result = await response.json()

      if (result.statusCode === 201) {
        // Redirect đến VNPay
        window.location.href = result.data.paymentUrl
      } else {
        throw new Error(result.message)
      }
    } catch (error) {
      console.error('Error creating order:', error)
      throw error
    }
  }

  // Xử lý return URL từ VNPay
  async handleReturnUrl() {
    try {
      const urlParams = new URLSearchParams(window.location.search)
      const verifyData = Object.fromEntries(urlParams.entries())

      const response = await fetch(`${this.baseUrl}/api/payment/vnpay/verify-return`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const result = await response.json()

      if (result.statusCode === 200 && result.data.isSuccess) {
        // Thanh toán thành công
        this.showSuccessMessage('Thanh toán thành công!')
        this.redirectToOrderPage()
      } else {
        // Thanh toán thất bại
        this.showErrorMessage('Thanh toán thất bại!')
        this.redirectToOrderPage()
      }
    } catch (error) {
      console.error('Error verifying payment:', error)
      this.showErrorMessage('Có lỗi xảy ra khi xác thực thanh toán!')
    }
  }

  // Hiển thị form thanh toán
  showPaymentForm(orderData) {
    const form = `
      <div class="vnpay-payment-form">
        <h3>Thanh toán qua VNPay</h3>
        <div class="order-summary">
          <p>Tổng tiền: ${orderData.totalAmount.toLocaleString('vi-VN')} VND</p>
          <p>Mã đơn hàng: ${orderData.orderId}</p>
        </div>
        <button onclick="vnpayPayment.createOrder(${JSON.stringify(orderData)})">
          Thanh toán ngay
        </button>
      </div>
    `
    document.getElementById('payment-container').innerHTML = form
  }

  showSuccessMessage(message) {
    // Hiển thị thông báo thành công
    alert(message)
  }

  showErrorMessage(message) {
    // Hiển thị thông báo lỗi
    alert(message)
  }

  redirectToOrderPage() {
    // Redirect về trang đơn hàng
    window.location.href = '/orders'
  }

  getToken() {
    // Lấy token từ localStorage hoặc cookie
    return localStorage.getItem('auth_token')
  }
}

// Sử dụng
const vnpayPayment = new VNPayPayment()

// Tạo đơn hàng
vnpayPayment.createOrder({
  items: [
    { productId: 'prod_123', quantity: 2, skuId: 'sku_456' }
  ],
  shippingAddress: {
    address: '123 Đường ABC',
    city: 'Hà Nội',
    phone: '0123456789'
  }
})

// Xử lý return URL (gọi khi user quay về từ VNPay)
if (window.location.pathname === '/payment/return') {
  vnpayPayment.handleReturnUrl()
}
```

### 2. React Component Example

```jsx
import React, { useState, useEffect } from 'react'

const VNPayPaymentComponent = ({ orderData, onSuccess, onError }) => {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const createPayment = async () => {
    try {
      setLoading(true)
      setError(null)

      const response = await fetch('/api/orders', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          ...orderData,
          paymentGateway: 'vnpay'
        })
      })

      const result = await response.json()

      if (result.statusCode === 201) {
        // Redirect đến VNPay
        window.location.href = result.data.paymentUrl
      } else {
        throw new Error(result.message)
      }
    } catch (error) {
      setError(error.message)
      onError?.(error)
    } finally {
      setLoading(false)
    }
  }

  const handleReturnUrl = async () => {
    try {
      const urlParams = new URLSearchParams(window.location.search)
      const verifyData = Object.fromEntries(urlParams.entries())

      const response = await fetch('/api/payment/vnpay/verify-return', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const result = await response.json()

      if (result.statusCode === 200 && result.data.isSuccess) {
        onSuccess?.(result.data)
      } else {
        throw new Error(result.message || 'Thanh toán thất bại')
      }
    } catch (error) {
      setError(error.message)
      onError?.(error)
    }
  }

  useEffect(() => {
    // Xử lý return URL khi component mount
    if (window.location.pathname === '/payment/return') {
      handleReturnUrl()
    }
  }, [])

  return (
    <div className="vnpay-payment">
      <h3>Thanh toán qua VNPay</h3>

      <div className="order-summary">
        <p>Tổng tiền: {orderData.totalAmount?.toLocaleString('vi-VN')} VND</p>
        <p>Mã đơn hàng: {orderData.orderId}</p>
      </div>

      {error && (
        <div className="error-message">
          {error}
        </div>
      )}

      <button
        onClick={createPayment}
        disabled={loading}
        className="payment-button"
      >
        {loading ? 'Đang xử lý...' : 'Thanh toán ngay'}
      </button>
    </div>
  )
}

export default VNPayPaymentComponent
```

## 🔗 Webhook và IPN

### 1. IPN URL Configuration

```typescript
// Trong createPayment request
{
  "ipnUrl": "https://your-domain.com/api/payment/vnpay/verify-ipn"
}
```

### 2. IPN Call Flow

VNPay sẽ gửi IPN call đến server của bạn với flow sau:

1. **VNPay gửi GET request** với tất cả thông tin thanh toán trong query parameters
2. **Server xác thực** checksum và xử lý logic business
3. **Server trả về text response** với mã cụ thể cho VNPay

```typescript
// VNPay gửi request đến endpoint này
GET https://your-domain.com/api/payment/vnpay/verify-ipn?vnp_Amount=100000&vnp_BankCode=NCB&vnp_OrderInfo=Thanh%20toan%20don%20hang%2012345&vnp_PayDate=20240115103000&vnp_ResponseCode=00&vnp_TmnCode=E12E8KYJ&vnp_TransactionNo=20240115103000&vnp_TransactionStatus=00&vnp_TxnRef=ORDER_12345&vnp_SecureHash=hash_string

// Server trả về text response
00  // Thành công
97  // Lỗi checksum
01  // Lỗi chung
```

### 3. WebSocket Integration

```javascript
// Client lắng nghe WebSocket events
import { io } from 'socket.io-client'

const socket = io('https://your-domain.com', {
  namespace: 'payment'
})

socket.on('payment', (data) => {
  if (data.status === 'success' && data.gateway === 'vnpay') {
    console.log('Payment successful via WebSocket!')
    // Update UI, show success message, etc.
  }
})

// Join user room
socket.emit('join', { userId: 'user_123' })
```

### 4. Server WebSocket Handler

```typescript
// Trong VNPayService
@WebSocketGateway({ namespace: 'payment' })
export class VNPayService {
  @WebSocketServer()
  server: Server

  async verifyIpnCall(queryData: VNPayReturnUrlType) {
    const verify = await this.vnpayService.verifyIpnCall(queryData)

    // Nếu xác thực thành công và thanh toán thành công
    if (verify.isSuccess && verify.isVerified && verify.vnp_ResponseCode === '00') {
      const userId = await this.vnpayRepo.processVNPayWebhook(queryData)

      // Gửi thông báo qua WebSocket
      this.server.to(`user_${userId}`).emit('payment', {
        status: 'success',
        gateway: 'vnpay'
      })
    }

    return verify
  }
}
```

### 5. IPN vs Return URL

| Aspect | IPN Call | Return URL |
|--------|----------|------------|
| **Method** | GET với query params | GET với query params |
| **Purpose** | Server-to-server notification | User redirect handling |
| **Response** | Text format (00/97/01) | JSON response |
| **Security** | High (server verification) | Medium (user can see) |
| **Business Logic** | ✅ Process payment | ❌ UI only |
| **Reliability** | ✅ Guaranteed delivery | ❌ User may close browser |

## ⚠️ Error Handling

### 1. Common Error Responses

```json
// Invalid Checksum
{
  "statusCode": 422,
  "message": "Chữ ký không hợp lệ",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "errors": [
    {
      "message": "payment.vnpay.error.VNPAY_INVALID_CHECKSUM",
      "path": "secureHash"
    }
  ]
}

// Duplicate Request
{
  "statusCode": 400,
  "message": "Yêu cầu trùng lặp",
  "timestamp": "2024-01-15T10:30:00.000Z"
}

// Service Unavailable
{
  "statusCode": 500,
  "message": "Dịch vụ VNPay không khả dụng",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### 2. Error Code Mapping

| Error Code | Description | HTTP Status |
|------------|-------------|-------------|
| `VNPAY_INVALID_CHECKSUM` | Chữ ký không hợp lệ | 422 |
| `VNPAY_INVALID_AMOUNT` | Số tiền không hợp lệ | 422 |
| `VNPAY_DUPLICATE_REQUEST` | Yêu cầu trùng lặp | 400 |
| `VNPAY_TRANSACTION_NOT_FOUND` | Không tìm thấy giao dịch | 422 |
| `VNPAY_SERVICE_UNAVAILABLE` | Dịch vụ không khả dụng | 500 |
| `VNPAY_TIMEOUT` | Yêu cầu bị timeout | 500 |
| `VNPAY_NETWORK_ERROR` | Lỗi kết nối mạng | 500 |

### 3. Client Error Handling

```javascript
class VNPayPayment {
  async handleError(response) {
    const errorData = await response.json()

    switch (errorData.statusCode) {
      case 422:
        if (errorData.errors?.[0]?.path === 'secureHash') {
          return 'Chữ ký thanh toán không hợp lệ. Vui lòng thử lại.'
        }
        return 'Dữ liệu thanh toán không hợp lệ.'

      case 400:
        return 'Yêu cầu trùng lặp. Vui lòng thử lại sau.'

      case 500:
        return 'Dịch vụ thanh toán tạm thời không khả dụng. Vui lòng thử lại sau.'

      default:
        return 'Có lỗi xảy ra. Vui lòng thử lại.'
    }
  }

  async createOrder(orderData) {
    try {
      const response = await fetch('/api/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(orderData)
      })

      if (!response.ok) {
        const errorMessage = await this.handleError(response)
        throw new Error(errorMessage)
      }

      const result = await response.json()
      return result
    } catch (error) {
      console.error('Payment error:', error)
      throw error
    }
  }
}
```

## 🧪 Testing

### 1. Test Environment Setup

```bash
# Environment variables cho testing
NODE_ENV=development
VNPAY_TMN_CODE=E12E8KYJ
VNPAY_SECURE_SECRET=VMZQECLOHDPXFBHLHMHYDLYIANSIHGQM
VNPAY_HOST=https://sandbox.vnpayment.vn
```

### 2. Test Card Numbers

```javascript
// Test card numbers cho VNPay sandbox
const testCards = {
  'NCB': '9704198526191432198',
  'VCB': '9704363894363878',
  'BIDV': '9704180004444444',
  'AGRIBANK': '9704034070668170666'
}
```

### 3. Test Script

```javascript
// test-vnpay.js
const axios = require('axios')

const BASE_URL = 'http://localhost:3000/api'

async function testVNPayIntegration() {
  try {
    // 1. Tạo đơn hàng
    console.log('1. Tạo đơn hàng...')
    const orderResponse = await axios.post(`${BASE_URL}/orders`, {
      items: [
        { productId: 'prod_123', quantity: 1, skuId: 'sku_456' }
      ],
      paymentGateway: 'vnpay',
      shippingAddress: {
        address: '123 Test Street',
        city: 'Hà Nội',
        phone: '0123456789'
      }
    })

    console.log('Order created:', orderResponse.data)

    // 2. Tạo payment URL
    console.log('2. Tạo payment URL...')
    const paymentResponse = await axios.post(`${BASE_URL}/payment/vnpay/create-payment`, {
      amount: 100000,
      orderInfo: 'Test payment',
      orderId: orderResponse.data.data.orderId,
      returnUrl: 'https://your-domain.com/payment/return',
      ipnUrl: 'https://your-domain.com/payment/ipn'
    })

    console.log('Payment URL:', paymentResponse.data.data.paymentUrl)

    // 3. Simulate return URL
    console.log('3. Simulate return URL...')
    const returnUrl = `${BASE_URL}/payment/vnpay/verify-return?vnp_Amount=100000&vnp_BankCode=NCB&vnp_OrderInfo=Test%20payment&vnp_PayDate=20240115103000&vnp_ResponseCode=00&vnp_TmnCode=E12E8KYJ&vnp_TransactionNo=20240115103000&vnp_TransactionStatus=00&vnp_TxnRef=${orderResponse.data.data.orderId}&vnp_SecureHash=test_hash`

    const verifyResponse = await axios.get(returnUrl)
    console.log('Verify response:', verifyResponse.data)

  } catch (error) {
    console.error('Test failed:', error.response?.data || error.message)
  }
}

testVNPayIntegration()
```

### 4. Manual Testing Steps

1. **Tạo đơn hàng với VNPay:**
   ```bash
   curl -X POST http://localhost:3000/api/orders \
     -H "Content-Type: application/json" \
     -d '{
       "items": [{"productId": "prod_123", "quantity": 1, "skuId": "sku_456"}],
       "paymentGateway": "vnpay",
       "shippingAddress": {"address": "123 Test", "city": "Hà Nội", "phone": "0123456789"}
     }'
   ```

2. **Tạo payment URL:**
   ```bash
   curl -X POST http://localhost:3000/api/payment/vnpay/create-payment \
     -H "Content-Type: application/json" \
     -d '{
       "amount": 100000,
       "orderInfo": "Test payment",
       "orderId": "ORDER_12345",
       "returnUrl": "https://your-domain.com/payment/return"
     }'
   ```

3. **Test verify return:**
   ```bash
   curl "http://localhost:3000/api/payment/vnpay/verify-return?vnp_Amount=100000&vnp_BankCode=NCB&vnp_OrderInfo=Test%20payment&vnp_PayDate=20240115103000&vnp_ResponseCode=00&vnp_TmnCode=E12E8KYJ&vnp_TransactionNo=20240115103000&vnp_TransactionStatus=00&vnp_TxnRef=ORDER_12345&vnp_SecureHash=test_hash"
   ```

4. **Test IPN endpoint:**
   ```bash
   curl "http://localhost:3000/api/payment/vnpay/verify-ipn?vnp_Amount=100000&vnp_BankCode=NCB&vnp_OrderInfo=Test%20payment&vnp_PayDate=20240115103000&vnp_ResponseCode=00&vnp_TmnCode=E12E8KYJ&vnp_TransactionNo=20240115103000&vnp_TransactionStatus=00&vnp_TxnRef=ORDER_12345&vnp_SecureHash=test_hash"
   ```
   **Expected Response:**
   ```json
   {
     "RspCode": "00",
     "Message": "Confirm Success"
   }
   ```

   **Lưu ý:** Response được trả về trực tiếp không qua interceptor để đảm bảo format đúng yêu cầu VNPay.

## 📝 Lưu Ý Quan Trọng

### 0. Implementation Notes

**⚠️ Thay đổi quan trọng trong IPN Implementation:**

1. **HTTP Method:** IPN endpoint sử dụng `GET` thay vì `POST`
2. **Parameters:** Nhận dữ liệu qua `@Query()` thay vì `@Body()`
3. **Response Format:** Trả về JSON response với `RspCode` và `Message`:
   - `00`, `02`: Thành công (VNPay kết thúc luồng)
   - `01`, `04`, `97`, `99`: Lỗi (VNPay retry)
4. **Response Interceptor:** Sử dụng `@SkipTransform()` decorator để bypass interceptor
5. **Order Status Management:** Sử dụng enum `OrderStatus` chuẩn:
   - Thành công: `OrderStatus.DELIVERED`
   - Thất bại: `OrderStatus.CANCELLED`
   - Kiểm tra trạng thái: `OrderStatus.DELIVERED` hoặc `OrderStatus.CANCELLED`
6. **Amount Validation:** Tính tổng tiền từ `productSKUSnapshot` items

**Lý do thay đổi:**
- Theo VNPay documentation, IPN call được gửi qua GET request với query parameters
- VNPay mong đợi JSON response với format `{RspCode: "00", Message: "Confirm Success"}`
- VNPay có cơ chế retry: tối đa 10 lần, mỗi 5 phút nếu nhận RspCode lỗi
- Đồng bộ với hệ thống order status management
- Tính toán amount chính xác từ order items

### 1. Order Status Management

**Order Status Flow:**
```typescript
// Kiểm tra trạng thái đã xử lý
if (existingOrder.status === OrderStatus.DELIVERED ||
    existingOrder.status === OrderStatus.CANCELLED) {
  return { RspCode: '02', Message: 'Order already confirmed' }
}

// Cập nhật trạng thái thành công
await this.prismaService.order.update({
  where: { id: orderId },
  data: { status: OrderStatus.DELIVERED }
})

// Cập nhật trạng thái thất bại
await this.prismaService.order.update({
  where: { id: orderId },
  data: { status: OrderStatus.CANCELLED }
})
```

**Amount Calculation:**
```typescript
// Tính tổng tiền từ order items
const items = await this.prismaService.productSKUSnapshot.findMany({
  where: { orderId: orderId }
})
const expectedAmount = items.reduce((sum, item) =>
  sum + item.skuPrice * item.quantity, 0) * 100
```

### 2. Security Considerations

- **HTTPS Required:** Tất cả API calls phải sử dụng HTTPS
- **Hash Verification:** Luôn verify hash từ VNPay
- **IP Whitelist:** Cấu hình IP whitelist cho production
- **Token Security:** Bảo vệ API tokens và secrets

### 2. Production Checklist

- [ ] Cấu hình production VNPay credentials
- [ ] Setup HTTPS certificates
- [ ] Configure IP whitelist
- [ ] Setup monitoring và logging
- [ ] Test webhook endpoints
- [ ] Configure error handling
- [ ] Setup backup và recovery

### 3. Common Issues và Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| Invalid checksum | Hash calculation error | Verify secure secret và hash algorithm |
| Duplicate request | Same order processed twice | Implement idempotency |
| Timeout | Network issues | Increase timeout settings |
| Amount mismatch | Currency conversion | Verify amount format |
| IPN not working | Wrong HTTP method | Use GET instead of POST for IPN |
| IPN response error | Wrong response format | Return text (00/97/01) not JSON |
| IPN not receiving | Wrong endpoint URL | Verify IPN URL configuration |

### 4. Performance Optimization

- **Caching:** Cache bank list và configuration
- **Connection Pooling:** Reuse HTTP connections
- **Async Processing:** Process webhooks asynchronously
- **Monitoring:** Monitor response times và error rates

## 📚 Tài Liệu Tham Khảo

- [VNPay Official Documentation](https://sandbox.vnpayment.vn/apis/docs/thanh-toan-pay/pay.html)
- [nestjs-vnpay Package](https://github.com/lehuygiang28/nestjs-vnpay)
- [vnpay Package](https://www.npmjs.com/package/vnpay)
- [VNPay API Reference](https://vnpay.js.org/)
- [NestJS Documentation](https://docs.nestjs.com/)
- [Socket.IO Documentation](https://socket.io/docs/)

## 🔧 Troubleshooting

### IPN Issues

**Problem:** IPN endpoint không nhận được calls từ VNPay
**Solution:**
- Verify IPN URL configuration trong VNPay merchant portal
- Ensure endpoint sử dụng GET method
- Check server logs cho incoming requests

**Problem:** IPN response error
**Solution:**
- Verify response format là JSON với `RspCode` và `Message`
- Return đúng format: `{"RspCode": "00", "Message": "Confirm Success"}`
- Check VNPay logs cho response errors

**Problem:** Checksum verification failed
**Solution:**
- Verify `VNPAY_SECURE_SECRET` configuration
- Check hash algorithm (SHA512)
- Ensure all required parameters được gửi

### Testing IPN Locally

```bash
# Test IPN endpoint với curl
curl "http://localhost:3000/api/payment/vnpay/verify-ipn?vnp_Amount=100000&vnp_BankCode=NCB&vnp_OrderInfo=Test&vnp_PayDate=20241219103000&vnp_ResponseCode=00&vnp_TmnCode=E12E8KYJ&vnp_TransactionNo=20241219103000&vnp_TransactionStatus=00&vnp_TxnRef=ORDER_12345&vnp_SecureHash=test_hash"

# Expected response: 00 (text format)
```

## 🤝 Support

Nếu gặp vấn đề, vui lòng:

1. Kiểm tra logs trong console
2. Verify configuration settings
3. Test với sandbox environment
4. Contact development team

---

## Changes

### Version 1.2.1 (2025-07-31)
- **Fix:** Sửa thứ tự logic trong IPN processing để kiểm tra amount trước payment status
- **Reason:** Đảm bảo test case "Invalid amount" hoạt động đúng thay vì trả về "Order already confirmed"
- **Impact:** Test case "Số tiền không hợp lệ" giờ sẽ trả về `RspCode: "04"` thay vì `RspCode: "02"`

### Version 1.2.0 (2025-07-31)
- **Fix:** Sửa logic tìm order từ orderId sang paymentId (giống Sepay)
- **Fix:** Cải thiện transaction handling với Prisma $transaction
- **Fix:** Tăng cường WebSocket notifications cho tất cả users liên quan
- **Fix:** Sửa response format cho IPN endpoint (bypass interceptor)
- **Reason:** Tất cả test cases đều trả về "Order not found" do logic lookup sai
- **Impact:** IPN endpoint giờ có thể tìm thấy payment và xử lý đúng các test cases

### Version 1.1.0 (2025-07-31)
- **Fix:** Thay đổi HTTP method từ POST sang GET cho IPN endpoint
- **Fix:** Thay đổi parameter từ @Body() sang @Query() cho IPN endpoint
- **Fix:** Thêm @SkipTransform() decorator để bypass response interceptor
- **Fix:** Cập nhật response format từ text sang JSON cho IPN
- **Reason:** VNPay gửi IPN qua query parameters, không phải request body
- **Impact:** IPN endpoint giờ nhận đúng format từ VNPay và trả về đúng format JSON

### Version 1.0.0 (2025-07-31)
- **Initial:** Triển khai VNPay payment gateway
- **Features:** Tạo payment, verify return URL, verify IPN, query DR, refund
- **Integration:** Tích hợp với WebSocket cho real-time notifications
