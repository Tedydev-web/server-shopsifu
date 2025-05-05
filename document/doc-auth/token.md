# Tư duy về thiết kế Authentication & Authorization cho website

- Stateless: Không lưu trạng thái ở server
- Stateful: Lưu trạng thái ở server, có thể là server hoặc redis
- Session: Phiên lưu trữ trạng thái của user, thường lưu ở DB hoặc Redis server.

## 1. Authentication

Hiện nay có khá nhiều kiểu xác thực, nhưng tui nhận thấy có 2 kiểu này là phổ biến nhất

| Kiểu xác thực   | Combo AT và RT                                                                                                                                                | Session Token (A.K.A 1 Access Token)                         |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| Access Token    | ✅, ngắn hạn (5-15p)                                                                                                                                          | ✅, thường dài (60 ngày)                                     |
| Refresh Token   | ✅, thường dài (60 ngày), để lấy access token mới                                                                                                             | ❌                                                           |
| Cách gia hạn    | Dùng Refresh Token                                                                                                                                            | Dùng Long-Lived Token                                        |
| State           | AT là Stateless, RT thường là Stateful (stateless cũng được, nhưng stateful sẽ bảo mật hơn)                                                                   | Stateful                                                     |
| Tốc độ xác thực | Nhanh, vì AT là stateless                                                                                                                                     | Chậm, vì cần phải query db mỗi lần xác thực request          |
| Bảo mật         | Thấp hơn, không revoke được access token. Nên nếu muốn cho 1 người dùng logout, chỉ có cách xóa refresh token của người đó và đợi access token của họ hết hạn | Cao, cần revoke token thì có thể revoke ngay lập tức         |
| Khả năng Scale  | Dễ, nếu có nhiều server (service trong microservice), chỉ cần verify token là xác thực đc request                                                         | Phức tạp hơn, phải query đến DB hoặc gọi đến API Gateway |

Ưu điểm của cái này là nhược điểm của cái kia. Quan trọng là hiểu app cần gì để chọn kiểu xác thực cho phù hợp

## 2. Authorization

API dùng Role và Permission để phân quyền, vậy làm sao để xác minh được User có permission của endpoint đó không?

- Ý tưởng 1: Lưu danh sách permission của user đó vào payload của access token. Giúp đảm bảo tính stateless của access token, nhưng không khả thi, vì số lượng permission quá lớn, payload sẽ rất nặng
- Ý tưởng 2: Lưu `roleId` vào payload của access token, mỗi request sẽ query `Permission` để lấy danh sách permission của role đó
- Ý tưởng 3: Dù gì thì cũng phải query db để lấy danh sách permission của user đó, chỉ cần `userId` trong payload của access token. Mỗi request sẽ query `User` để lấy danh sách permission của user đó (sẽ lâu hơn ý tưởng 2 một chút xíu, vì phải join table `User`, `Role` và `Permission`)

Khả thi nhất là ý tưởng 2 và 3:

| Ý tưởng | Lưu `roleId` vào payload AT                                                                       | Lưu userId vào payload AT                            |
| ------- | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Tốc độ  | Nhanh hơn                                                                                         | Chậm hơn (một ít)                                    |
| Bảo mật | Thấp hơn 1 tí, vì nếu cập nhật lại `roleId` của user thì access token không thể cập nhật lại ngay | Cao. Vì `roleId` không lưu vào access token của user |

2 ý tưởng trên hoạt động tuyệt vời với trường hợp thay đổi permission của role. Chỉ khác nhau ở cấp độ thay đổi role của user

Nếu hệ thống không thường xuyên thay đổi role của user, Ví dụ như hơn 1 ngày mới thay đổi role 1 lần của user, thì ý tưởng 2 sẽ phù hợp hơn. Nó còn dễ dàng dùng Redis caching để tăng hiệu suất và giảm tải cho database

Nếu hệ thống thường xuyên thay đổi role của user, vài giờ thay đổi 1 lần, thì ý tưởng 3 sẽ phù hợp hơn. Nó ảnh hưởng ngay lập tức đến user.

## 3. Quản lý thiết bị login

Bây giờ nếu muốn làm chức năng quản lý được bao nhiêu thiết bị đã login, chủ động đăng xuất thiết bị đó từ 1 thiết bị khác thì

sẽ tạo 1 table gồm các trường sau

```prisma

model User {
  //...
  devices      Device[]      // Liên kết 1-n với Device
}
model Device {
  id           Int           @id @default(autoincrement())
  userId       Int
  user         User          @relation(fields: [userId], references: [id], onDelete: Cascade, onUpdate: NoAction)
  userAgent    String
  ip           String
  lastActive   DateTime      @updatedAt // Thay updatedAt bằng lastActive cho ý nghĩa rõ hơn
  createdAt    DateTime      @default(now())
  isActive     Boolean       @default(true) // Trạng thái thiết bị (đang login hay đã logout)
  refreshTokens RefreshToken[] // Liên kết 1-n với RefreshToken
}

model RefreshToken {
  token     String    @unique @db.VarChar(1000)
  userId    Int
  user      User      @relation(fields: [userId], references: [id], onDelete: Cascade, onUpdate: NoAction)
  deviceId  Int      // Foreign key tới Device
  device    Device   @relation(fields: [deviceId], references: [id],  onDelete: Cascade, onUpdate: NoAction)
  expiresAt DateTime
  createdAt DateTime  @default(now())
  @@index([expiresAt])
}
```

### Flow Login

- Tạo record `Device` mới
- Tạo Access Token và record `RefreshToken`

Payload AT

```json
{
  "userId": 123,
  "deviceId": 1,
  "roleId": 1,
  "roleName": "CLIENT" // Nếu muốn dễ debug, có thể lưu roleName vào payload AT, còn không thì `roleId` là đủ
}
```

Payload RT

```json
{
  "userId": 123
}
```

- Trả AT và RT về client

### Flow Refresh Token

- Kiểm tra xem RT có hợp lệ không
- Cập nhật `userAgent`, `ip`, `lastActive`, `isActive=true` cho `Device`
- Xóa RT cũ, tạo RT mới
- Trả AT và RT mới về client

### Flow middleware

Mỗi request đi qua, sẽ

1. Kiểm tra xem AT có hợp lệ không, còn hạn hay không. Từ đó lấy ra `userId` và `roleId`
2. Dựa `roleId` vào để query database lấy danh sách permission của role đó
3. Kiểm tra danh sách permission của role đó có quyền truy cập endpoint đó không

có thể thêm sau bước 2 là: Dựa vào `deviceId` query `Device` để kiểm tra xem thiết bị đó có `isActive=true` không từ đó quyết định cho phép hoặc không cho phép request đi qua. Lúc này đã có thể làm được chức năng đăng xuất thiết bị ngay lập tức. Nhưng đánh đổi là phải tốn 1 query (hoặc thêm 1 vài lần join table), điều này làm tăng latency và tăng gánh nặng lên database, nhất là khi có nhiều người request.

Vì thế, vẫn chọn giữ nguyên cách làm ở trên
