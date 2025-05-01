# Giao Diện Người Dùng: Cài Đặt Xác Thực 2 Yếu Tố (Setup 2FA)

**File:** `ui-setup-2fa.md`
**Ngày tạo:** 2025-04-30

---

## Mục Tiêu (Goal)

Cho phép người dùng đã đăng nhập kích hoạt tính năng Xác thực 2 yếu tố (2FA) dựa trên TOTP (Time-based One-Time Password) sử dụng ứng dụng Authenticator.

---

## API Endpoint Liên Quan (Related API Endpoint)

* `POST /auth/setup-2fa` (Yêu cầu người dùng đã được xác thực - authenticated)

---

## Luồng Logic Backend (Backend Logic Flow - Summary)

1.  **`setupTwoFactorAuth`**:
    * Lấy thông tin `user` dựa trên `userId` (từ token/session). Ném `EmailNotFoundException` nếu user không tồn tại (lỗi hệ thống).
    * Kiểm tra xem `user.totpSecret` đã có giá trị chưa. Nếu **CÓ**, ném `TOTPAlreadyEnabledException`.
    * Nếu **CHƯA CÓ**:
        * Gọi `twoFactorService.generateTOTPSecret` để tạo `secret` và `uri` (dùng cho QR code).
        * **Cập nhật (lưu) `secret` vào bản ghi `user` trong database.**
        * Trả về `{ secret, uri }`.

---

## Các Thành Phần Giao Diện (UI Components)

*(Thường nằm trong trang Cài đặt Tài khoản / Bảo mật)*

* **Khu Vực Quản Lý 2FA (`<div class="two-factor-settings">`)**:
    * **Trạng Thái Hiện Tại (`<p>`)**: Hiển thị "Xác thực 2 yếu tố: **Đang tắt**" hoặc "**Đang bật**".
    * **Nút Bật 2FA (`<button type="button" id="enable-2fa-btn">`)**:
        * Text: "Bật Xác Thực 2 Yếu Tố"
        * *Hiển thị khi 2FA đang tắt.*
        * *Trạng thái:* Disable khi đang xử lý.
* **Khu Vực Hướng Dẫn Cài Đặt (`<div id="setup-2fa-instructions" style="display: none;">`)**: *Hiển thị sau khi nhấn "Bật 2FA"*
    * **Tiêu đề**: "Cài đặt Xác thực 2 yếu tố"
    * **Bước 1: Cài đặt Ứng dụng**: "Cài đặt ứng dụng Google Authenticator, Authy hoặc tương tự."
    * **Bước 2: Quét Mã QR**:
        * Hiển thị Mã QR Code (`<div id="qr-code"></div>` - Sử dụng thư viện để render từ `uri`).
        * Thông báo: "Quét mã QR này bằng ứng dụng Authenticator của bạn."
    * **Hoặc Nhập Thủ Công**:
        * Hiển thị Mã Bí Mật (`<p>`) : "Hoặc nhập mã bí mật này thủ công:"
        * Hiển thị `secret` (`<code id="secret-key">{secretValue}</code>`).
        * Nút Copy Secret (`<button type="button" id="copy-secret-btn">`)
    * **CẢNH BÁO QUAN TRỌNG (`<div class="warning">`)**: "**LƯU Ý:** Hãy ghi lại Mã Bí Mật này và cất giữ ở nơi an toàn. Mã này dùng để khôi phục quyền truy cập nếu bạn mất điện thoại."
    * **Bước 3: Xác nhận (Optional - Nên có)**:
        * Label: "Nhập mã gồm 6 chữ số từ ứng dụng của bạn để xác nhận:"
        * TOTP Xác Nhận Input (`<input type="text" name="verifyTotpCode">`)
        * Nút Hoàn Tất Cài Đặt (`<button type="button" id="complete-setup-btn">`)
            * Text: "Xác Nhận và Hoàn Tất"
    * **Vùng Thông Báo (`<div class="setup-feedback">`)**: Hiển thị lỗi hoặc thành công.

---

## Luồng Tương Tác Người Dùng (User Interaction Workflow)

*(Giả định người dùng đã đăng nhập và đang ở trang Cài đặt)*

1.  Giao diện hiển thị trạng thái 2FA là "Đang tắt".
2.  Người dùng nhấn nút **"Bật Xác Thực 2 Yếu Tố"**.
    * **Frontend:** Disable nút. Hiển thị loading.
    * **Frontend Call API:** `POST /auth/setup-2fa` (Gửi kèm token xác thực).
    * **Xử lý Response:**
        * **Thành công (2xx - Trả về `{ secret, uri }`):**
            * Ẩn loading.
            * **Hiển thị Khu Vực Hướng Dẫn Cài Đặt (`#setup-2fa-instructions`)**.
            * Render QR Code từ `uri` vào `#qr-code`.
            * Hiển thị `secret` trong `#secret-key`.
            * Ẩn nút "Bật Xác Thực 2 Yếu Tố" ban đầu.
        * **Thất bại (4xx/5xx):**
            * Enable lại nút. Ẩn loading.
            * Hiển thị lỗi:
                * `TOTPAlreadyEnabledException`: "Xác thực 2 yếu tố đã được bật trước đó."
                * Lỗi khác (ví dụ: 401 Unauthorized nếu token hết hạn): "Không thể thực hiện. Vui lòng đăng nhập lại."

3.  **Nếu Khu Vực Hướng Dẫn được hiển thị:**
    * Người dùng thực hiện theo hướng dẫn: Cài app, quét QR hoặc nhập secret.
    * **Nếu có Bước 3 (Xác nhận - Recommended):**
        * Người dùng nhập mã TOTP từ ứng dụng vào **TOTP Xác Nhận Input**.
        * Người dùng nhấn **"Xác Nhận và Hoàn Tất"**.
            * **Frontend:** (Logic này cần API riêng để xác minh mã TOTP, vì `setupTwoFactorAuth` không làm việc này). Giả sử có API `POST /auth/verify-setup-2fa` nhận `{ totpCode }`.
            * **Frontend Call API:** `POST /auth/verify-setup-2fa` với `{ totpCode }`.
            * **Xử lý Response:**
                * **Thành công:** Ẩn Khu vực Hướng Dẫn. Cập nhật Trạng Thái Hiện Tại thành "Đang bật". Hiển thị nút "Tắt Xác Thực 2 Yếu Tố". Hiển thị thông báo thành công ("Đã bật xác thực 2 yếu tố thành công!").
                * **Thất bại:** Hiển thị lỗi ("Mã xác nhận không đúng. Vui lòng thử lại.").
    * **Nếu không có Bước 3 (Xác nhận):**
        * Sau khi hiển thị hướng dẫn, có thể coi như 2FA đã được "kích hoạt" ở backend (vì secret đã được lưu). Cần có nút "Đã hiểu/Đóng" để ẩn khu vực hướng dẫn và cập nhật trạng thái UI thành "Đang bật". **Tuy nhiên, cách này kém an toàn hơn.**

---

## Xử Lý Trạng Thái & Phản Hồi (State Management & Feedback)

* Quản lý trạng thái 2FA hiện tại của người dùng (`is2FAEnabled`).
* Quản lý trạng thái hiển thị khu vực hướng dẫn cài đặt (`showSetupInstructions`).
* Quản lý trạng thái loading.
* Render QR code bằng thư viện phù hợp (ví dụ: `qrcode.react`, `ngx-qrcode`).
* Triển khai chức năng copy mã secret vào clipboard.

---

## Validation Phía Client (Client-Side Validation)

* *(Nếu có bước xác nhận)* Kiểm tra định dạng mã TOTP (6 chữ số).

---

## Lưu Ý Cho Intern (Notes for Intern)

* Chức năng này yêu cầu người dùng phải **đăng nhập** trước. Đảm bảo API call được gửi kèm token xác thực hợp lệ.
* Backend **đã lưu secret** ngay khi API `setupTwoFactorAuth` thành công, *trước cả khi* người dùng xác nhận đã quét QR/lưu secret. UI cần hướng dẫn người dùng **lưu secret ngay lập tức**.
* Bước xác nhận bằng cách nhập mã TOTP sau khi cài đặt (Bước 3) là **best practice** để đảm bảo người dùng thiết lập đúng, nhưng cần backend hỗ trợ thêm API endpoint (`verify-setup-2fa`). Nếu không có, phải dựa vào việc backend đã lưu secret và chỉ hiển thị trạng thái "Bật" sau khi người dùng xem hướng dẫn.
* Nhấn mạnh tầm quan trọng của việc lưu mã secret dự phòng.