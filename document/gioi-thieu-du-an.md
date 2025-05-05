# Giới thiệu dự án

Thiết kế 1 website bán hàng tương tự Shopee với các chức năng sau:

- Có 3 vai trò chính: Khách hàng, Người bán (Seller), Admin

- Admin có thể quản lý tất cả các chức năng của website

- Người bán có thể đăng sản phẩm, quản lý sản phẩm, xem lịch sử bán hàng đánh giá khách hàng

- Khách hàng có thể xem sản phẩm, thêm vào giỏ hàng, mua hàng, xem lịch sử mua hàng, đánh giá sản phẩm

## Một số chức năng đặc biệt

- Sử dụng Access Token và Refresh Token cho Authentication, nhưng vẫn quản lý được số lượng thiết bị đăng nhập

- Áp dụng xác thực 2 yếu tố (2FA)

- Phân quyền dựa trên Role và Permission

- Sản phẩm chứa nhiều biến thể như size, màu, số lượng, giá,... (Product Variant)

- Thanh toán đơn hàng online bằng mã QR Code

- Gửi mail thông báo định kỳ cho khách hàng khi có sản phẩm mới (Cron Job)

## Phân tích sơ bộ các đối tượng cần tạo bảng

- **Language**: id, name, code
- **User**: id, name, email, password
- **UserTranslation**: id, userId, languageId, description, address
- **RefreshToken**: token, userId

Để phục vụ cho việc gửi mã OTP 6 số về email khi register hoặc forgot password, cần tạo thêm bảng để lưu mã OTP

- **VerificationCode**: id, email, code, expiresAt

Để phục vụ phân quyền Role và Permission thì

- **Role**: id, name, isActive
- **Permission**: id, name, path, method

> Quan hệ giữa **Role** và **Permission** là n-n, nên cần tạo bảng trung gian (RolePermission)

Liên quan đến sản phẩm

- **Product**: id, price, categoryId
- **ProductTranslation**: id, productId, languageId, name, description
- **Category**: id, parentCategoryId
- **CategoryTranslation**: id, categoryId, languageId, name
- **Brand**: id, logo
- **BrandTranslation**: id, brandId, languageId, name

> Quan hệ giữa **Product** và **Category** là n-n, nên cần tạo bảng trung gian (ProductCategory)
> 1 **Category** cha có thể có nhiều **Category** con, nên cần tạo thêm cột `parentCategoryId` trong bảng **Category**. Đây gọi là **tự** quan hệ 1-n

Hỗ trợ Product Variant

- **Variant**: id, name, productId
- **VariantOption**: id, value, variantId
- **SKU**: id, value, price, stock, images, productId

> Quan hệ giữa **VariantOption** và **SKU** là n-n, nên cần tạo bảng trung gian (VariantOptionSKU)

Hỗ trợ mua hàng

- **CartItem**: id, userId, skuId, quantity
- **ProductSKUSnapshot** (clone sản phẩm sku lúc đó, đề phòng sau này sản phẩm bị thay đổi thì không ảnh hưởng đến lịch sử mua hàng): id, productName, price, images, skuValue, skuId, orderId
- **Order**: id, userId, status

Hỗ trợ đánh giá sản phẩm

- **Review**: id, userId, productId, rating, content

Hỗ trợ thông tin thanh toán chuyển khoản

- **PaymentTransaction** (Đây là payload mà cổng thanh toán bắn cho khi có 1 ai đó chuyển khoản vào bank): id, gateway, transactionDate, accountNumber, code, body,...

Chức năng nhắn tin

- **Message**: id, fromUserId, toUserId, content, isReadAt

FAQ:

1. Tại sao cần tạo bảng **VerificationCode** mà không gọp vào bảng **User**?

Liên quan đến flow đăng ký tài khoản

Tui muốn verify email trước khi người dùng nhấn submit đăng ký tài khoản, điều này giúp tránh được email rác cũng như là xung đột email giữa các user

---
