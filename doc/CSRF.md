# CSRF Protection trong Shopsifu

## Cơ chế bảo vệ CSRF

Shopsifu sử dụng bảo vệ CSRF (Cross-Site Request Forgery) dựa trên cơ chế Double Submit Cookie để bảo vệ người dùng khỏi các cuộc tấn công CSRF.

### Cách hoạt động

1. Khi người dùng truy cập hệ thống, server sẽ sinh một CSRF token và đặt nó vào cookie `xsrf-token`.
2. Token này cũng được trả về trong header HTTP `x-csrf-token`.
3. Khi thực hiện các request thay đổi dữ liệu (POST, PUT, DELETE), client phải gửi token này trong header `X-CSRF-Token`.
4. Server sẽ so sánh token trong cookie với token trong header, nếu khớp thì request hợp lệ.

## Testing CSRF

Để test CSRF, sử dụng lệnh đã được cấu hình sẵn:

```bash
npm run test:csrf
```

Hoặc thủ công:

```bash
# Bước 1: Lấy CSRF token
curl -v -X GET http://localhost:3000/api/v1/ -c cookies.txt

# Kiểm tra token trong file cookies.txt
cat cookies.txt | grep xsrf-token

# Bước 2: Sử dụng token trong request tiếp theo
curl -v -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: ZoJI8zCX-UDvSP_-X5G0iXgX_5IUJgwv2ej4" \
  -b cookies.txt \
  -d '{
    "email": "hieudat2310.bh@gmail.com",
    "password": "Shopsifu2025@@"
  }'
```

## Lưu ý quan trọng

- Header CSRF phải là `x-csrf-token` (chữ thường)
- Cookie CSRF có tên `xsrf-token` (chữ thường)
- Token trong header và cookie phải giống hệt nhau
- Cookie CSRF được cấu hình với `httpOnly: false` để JavaScript có thể đọc
- Cookie CSRF được cấu hình với `sameSite: 'lax'` để hoạt động tốt với các ứng dụng SPA
- CSRF protection được áp dụng cho tất cả các endpoint ngoại trừ:
  - `/api/v1/auth/google/callback`
  - `/api/v1/webhook`
  - `/api/v1/health`
- Tất cả phương thức GET, HEAD, OPTIONS đều được bỏ qua CSRF protection

## Triển khai trong Frontend

Khi triển khai trong frontend, cần đảm bảo:

1. **Lấy token CSRF từ cookie**:

```javascript
const csrfToken = document.cookie
  .split('; ')
  .find((row) => row.startsWith('xsrf-token='))
  ?.split('=')[1]
```

2. **Thêm token vào mọi request không phải GET**:

```javascript
// Axios
axios.defaults.headers.post['X-CSRF-Token'] = csrfToken
axios.defaults.headers.put['X-CSRF-Token'] = csrfToken
axios.defaults.headers.delete['X-CSRF-Token'] = csrfToken

// Fetch
fetch('/api/endpoint', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken
  },
  body: JSON.stringify(data)
})
```

3. **Cấu hình Axios với withCredentials**:

```javascript
// Đây là một bước quan trọng để đảm bảo cookies được gửi cùng request
axios.defaults.withCredentials = true
```

## Xử lý lỗi

Nếu gặp lỗi "Invalid CSRF token", kiểm tra các vấn đề sau:

1. **Thiếu header CSRF**: Đảm bảo gửi header `X-CSRF-Token` trong mọi request không phải GET
2. **Cookie không đúng**: Kiểm tra cookie `xsrf-token` có tồn tại trong browser hay không
3. **Token không khớp**: Đảm bảo token trong header và cookie giống nhau
4. **CORS vấn đề**: Đảm bảo CORS đã được cấu hình đúng với `credentials: true`
5. **Cookie không được gửi**: Thêm `withCredentials: true` cho các AJAX requests
6. **Cookie đã hết hạn**: Thực hiện một request GET mới để nhận token mới

### Các bước debug phổ biến:

1. Kiểm tra Request Headers có chứa `X-CSRF-Token`
2. Kiểm tra Cookie Headers có chứa `xsrf-token`
3. So sánh giá trị của cả hai, chúng phải giống hệt nhau
4. Kiểm tra console.log trong server để xem lỗi chi tiết

## Cấu trúc code

CSRF middleware được triển khai trong `src/shared/middleware/csrf.middleware.ts` và được đăng ký toàn cục trong `app.module.ts`.

Constants liên quan đến CSRF được định nghĩa trong `src/shared/constants/auth.constant.ts`.
