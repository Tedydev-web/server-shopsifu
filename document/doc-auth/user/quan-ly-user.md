# Yêu cầu về quản lý user

Hệ thống coi Admin là quyền hạn quản lý cao nhất, giống như `root` hay `superuser` trong một số hệ thống khác.

Nếu muốn quản lý người dùng, có thể dùng role admin hoặc giải pháp an toàn hơn là tạo thêm một role `manager` hoặc `sub-admin` để quản lý user. Cho dù các role này add full permissions thì vẫn bị một số hạn chế không được như role admin.

Mọi Role có permissions đến các API user đều có thể gọi nhưng có 1 số lưu ý

## Tạo user: POST /users

```json
{
  "email": "hieudat2310.bh@gmail.com",
  "name": "Hiếu Đạt",
  "phoneNumber": "0869685621",
  "avatar": "google.com",
  "password": "123456",
  "roleId": 1,
  "status": "ACTIVE"
}
```

- Chỉ có Role Admin mới được tạo user với roleId là admin

## Cập nhật user: PUT /users/:userId

body tương tự như tạo user

```json
{
  "email": "hieudat2310.bh@gmail.com",
  "name": "Hiếu Đạt",
  "phoneNumber": "0869685621",
  "avatar": "google.com",
  "password": "123456",
  "roleId": 2,
  "status": "ACTIVE"
}
```

- Chỉ có Role Admin mới được cập nhật user với roleId là admin, hoặc lên cấp role thành admin
- không thể cập nhật chính mình

## Xóa user: DELETE /users/:userId

- Chỉ có Role Admin mới được xóa user với roleId là admin
- không thể xóa chính mình

## Lấy danh sách user: GET /users

- Hỗ trợ phân trang
- Trả về kết quả kèm role name trong từng user

## Lấy thông tin user: GET /users/:userId

- Trả về kết quả tương tự api get profile cá nhân
