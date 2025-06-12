## **TÀI LIỆU HƯỚNG DẪN TÍCH HỢP HỆ THỐNG PHÂN QUYỀN CHO CLIENT NEXT.JS**

**Mục lục:**

1.  **Giới thiệu**
    - Mục đích tài liệu
    - Tổng quan về hệ thống phân quyền backend
2.  **Các Khái niệm Cốt lõi**
    - Permission (`action`, `subject`)
    - Conditions (JSON Logic)
    - UI Metadata
3.  **Luồng Xác thực (Authentication Flow)**
    - Các Endpoint chính
    - Quản lý Token
4.  **Bước Quan trọng: Lấy Thông tin Quyền hạn Người dùng (`/auth/ui-capabilities`)**
    - Endpoint và thời điểm gọi
    - Cấu trúc dữ liệu trả về
5.  **Chiến lược Quản lý Quyền hạn Phía Client**
    - Lưu trữ dữ liệu quyền hạn
    - Xây dựng `PermissionService` hoặc `usePermissions` Hook
6.  **Tích hợp Phân quyền vào Ứng dụng Next.js**
    - Bảo vệ Route (Trang)
    - Render UI Động dựa trên Quyền
    - Sử dụng `conditions` và `ui_metadata`
7.  **Tương tác với API Backend**
    - Gửi Request đã xác thực
    - Xử lý Phản hồi từ API
8.  **Best Practices và Lưu ý Quan trọng**
9.  **Tóm tắt Luồng Hoạt động Mẫu**

---

### **1. Giới thiệu**

#### **1.1. Mục đích tài liệu**

Tài liệu này cung cấp hướng dẫn chi tiết cho các nhà phát triển Next.js về cách tích hợp và sử dụng hiệu quả hệ thống phân quyền của backend. Mục tiêu là giúp bạn xây dựng một ứng dụng client an toàn, linh hoạt và mang lại trải nghiệm người dùng tốt nhất.

#### **1.2. Tổng quan về hệ thống phân quyền backend**

Hệ thống backend cung cấp một cơ chế phân quyền mạnh mẽ dựa trên:

- **Role-Based Access Control (RBAC):** Người dùng được gán vai trò (Role).
- **Permissions:** Mỗi vai trò có một tập hợp các quyền (Permission) cụ thể.
- **Conditions:** Quyền có thể đi kèm điều kiện động (JSON Logic) để kiểm soát truy cập dựa trên ngữ cảnh.
- **UI Metadata:** Quyền có thể chứa metadata để hỗ trợ việc render UI động phía client.

---

### **2. Các Khái niệm Cốt lõi**

#### **2.1. Permission (`action`, `subject`)**

Một `Permission` định nghĩa một hành động (`action`) có thể được thực hiện trên một đối tượng hoặc tài nguyên (`subject`).

- **`action`**: (string) Động từ mô tả hành động (ví dụ: `create`, `read`, `update`, `delete`, `manage`, `read:own`).
- **`subject`**: (string) Danh từ mô tả đối tượng/tài nguyên (ví dụ: `User`, `Product`, `Order`, `Settings`).

#### **2.2. Conditions (JSON Logic)**

- **Mục đích:** Cho phép định nghĩa các quy tắc truy cập động. Một permission chỉ có hiệu lực nếu `conditions` của nó (nếu có) được đánh giá là `true` trong ngữ cảnh hiện tại.
- **Định dạng:** Một đối tượng JSON tuân theo cú pháp [JSON Logic](https://jsonlogic.com/).
- **Ví dụ:**
  ```json
  // Chỉ cho phép user cập nhật bài viết của chính họ
  { "==": [{ "var": "user.id" }, { "var": "resource.authorId" }] }
  ```
- **Đánh giá:** Backend sẽ đánh giá `conditions` một cách nghiêm ngặt. Client có thể (và nên) đánh giá `conditions` để cải thiện UX, nhưng không được coi đây là biện pháp bảo mật.

#### **2.3. UI Metadata (`ui_metadata`)**

- **Mục đích:** Cung cấp dữ liệu cho client để render các thành phần UI một cách động và nhất quán, dựa trên quyền hạn.
- **Định dạng:** Một đối tượng JSON tự do, có thể chứa thông tin như:
  - `label`: Nhãn hiển thị cho button, menu item.
  - `icon`: Tên icon.
  - `color`: Màu sắc.
  - `order`: Thứ tự hiển thị.
  - `tooltip`: Chú giải.
  - `formConfiguration`: Cấu hình cho các trường form.
  - `visibilityRules`: Quy tắc ẩn/hiện dựa trên ngữ cảnh khác.
- **Ví dụ:**
  ```json
  { "label": "Tạo Người dùng Mới", "icon": "user-plus", "color": "primary" }
  ```

---

### **3. Luồng Xác thực (Authentication Flow)**

#### **3.1. Các Endpoint chính**

Client sẽ sử dụng các endpoint sau của backend để xác thực:

- **Đăng nhập:** `POST /auth/login` (Body: `{ emailOrUsername, password, rememberMe? }`)
- **Đăng ký:**
  - `POST /auth/initiate-registration` (Body: `{ email }`)
  - `POST /auth/complete-registration` (Body: `{ password, confirmPassword, ... }`, cần `slt_token` từ bước trước)
- **Làm mới Token:** `POST /auth/refresh-token` (Không cần body, dựa vào `refresh_token` cookie)
- **Đăng xuất:** `POST /auth/logout`
- **Xác thực qua Mạng xã hội:** `GET /auth/social/{provider}` và callback tương ứng.
- **Quản lý OTP, 2FA, Mật khẩu:** Tham khảo tài liệu API backend chi tiết cho các flow này.

#### **3.2. Quản lý Token**

- Backend sử dụng cơ chế dual-token:
  - **`access_token`**: Token truy cập ngắn hạn, được gửi trong HTTP-only cookie (hoặc Authorization header nếu client quản lý).
  - **`refresh_token`**: Token làm mới dài hạn hơn, được gửi trong HTTP-only cookie.
- **Client:**
  - Nếu backend set token qua HTTP-only cookie, trình duyệt sẽ tự động gửi kèm.
  - Client cần có logic để tự động gọi `POST /auth/refresh-token` khi `access_token` hết hạn (thường là khi nhận được lỗi `401 Unauthorized` từ API).

---

### **4. Bước Quan trọng: Lấy Thông tin Quyền hạn Người dùng (`/auth/ui-capabilities`)**

Đây là endpoint **quan trọng nhất** cho việc quản lý phân quyền phía client.

#### **4.1. Endpoint và thời điểm gọi**

- **Endpoint:** `GET /auth/ui-capabilities`
- **Yêu cầu:** Cần `access_token` hợp lệ.
- **Thời điểm gọi:**
  1.  **Một lần** ngay sau khi người dùng đăng nhập thành công.
  2.  **Một lần** khi ứng dụng Next.js tải lại hoàn toàn (full page reload) nếu người dùng đã có phiên đăng nhập hợp lệ.

#### **4.2. Cấu trúc dữ liệu trả về (Ví dụ)**

```json
{
  "user": {
    "id": 123,
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe"
    // ... các thông tin cơ bản khác của người dùng
  },
  "role": {
    "id": 1,
    "name": "Administrator",
    "description": "Full access to all system features"
  },
  "permissions": [
    {
      "action": "create",
      "subject": "User",
      "conditions": null, // Hoặc một đối tượng JSON Logic
      "ui_metadata": {
        "label": "Thêm Người dùng",
        "icon": "FaUserPlus",
        "category": "User Management"
      }
    },
    {
      "action": "read",
      "subject": "User",
      "conditions": null,
      "ui_metadata": {
        /* ... */
      }
    },
    {
      "action": "update",
      "subject": "Profile",
      "conditions": {
        // Chỉ cho phép cập nhật profile của chính mình
        "==": [{ "var": "user.id" }, { "var": "resource.id" }]
      },
      "ui_metadata": { "label": "Cập nhật Hồ sơ" }
    }
    // ... nhiều permissions khác
  ],
  "features": {
    // Các tính năng được kích hoạt cho người dùng/role này
    "betaFeatureX": true,
    "advancedReporting": false
  }
}
```

- **`user`**: Thông tin cơ bản của người dùng đang đăng nhập.
- **`role`**: Thông tin về vai trò hiện tại của người dùng.
- **`permissions`**: Mảng chứa tất cả các `Permission` mà người dùng này có quyền, bao gồm `action`, `subject`, `conditions` (nếu có), và `ui_metadata` (nếu có).
- **`features`**: Một đối tượng key-value cho biết các cờ tính năng (feature flags) nào được bật cho người dùng.

---

### **5. Chiến lược Quản lý Quyền hạn Phía Client**

#### **5.1. Lưu trữ dữ liệu quyền hạn**

- Lưu trữ toàn bộ response từ `GET /auth/ui-capabilities` vào một **global state** của Next.js.
- Các lựa chọn phổ biến: React Context API, Zustand, Redux, Jotai.
- Điều này đảm bảo dữ liệu quyền hạn có thể được truy cập nhanh chóng từ bất kỳ component nào mà không cần gọi lại API.

#### **5.2. Xây dựng `PermissionService` hoặc `usePermissions` Hook**

Tạo một module (service class hoặc custom React hook) để tập trung logic kiểm tra quyền. Ví dụ: `usePermissions()`.

**Các hàm/phương thức cốt lõi cần có:**

1.  **`can(action: string, subject: string, resourceContext?: object): boolean`**

    - **Mục đích:** Kiểm tra xem người dùng hiện tại có quyền thực hiện `action` trên `subject` hay không, có tính đến `conditions` nếu được cung cấp `resourceContext`.
    - **Logic:**
      1.  Tìm permission tương ứng (`action`, `subject`) trong danh sách permissions đã lưu (từ `/auth/ui-capabilities`).
      2.  Nếu không tìm thấy permission, trả về `false`.
      3.  Nếu permission được tìm thấy và **không** có `conditions`, trả về `true`.
      4.  Nếu permission có `conditions`:
          - Sử dụng một thư viện JSON Logic phía client (ví dụ: `json-logic-js`).
          - Đánh giá `conditions` đó với dữ liệu được cung cấp trong `resourceContext`. `resourceContext` nên chứa thông tin về người dùng hiện tại (`user` từ global state) và thông tin về tài nguyên đang được tương tác (ví dụ: `{ resource: { id: 123, ownerId: 456 } }`).
          - Trả về kết quả của việc đánh giá JSON Logic.
    - **`resourceContext` (Ví dụ):**
      ```javascript
      // Khi kiểm tra quyền cập nhật một bài viết cụ thể
      const context = {
        user: currentUserFromGlobalState, // { id: 123, department: 'Sales', ... }
        resource: {
          // Thông tin về bài viết đang được xem/chỉnh sửa
          id: 'post-abc',
          authorId: 123,
          status: 'published'
        }
      }
      permissionService.can('update', 'Post', context)
      ```
    - **LƯU Ý QUAN TRỌNG:** Việc đánh giá `conditions` ở client chỉ nhằm mục đích **cải thiện trải nghiệm người dùng** (UX) - ví dụ, ẩn/hiện nút ngay lập tức. **Backend LUÔN LUÔN là nơi thực thi kiểm tra `conditions` cuối cùng và mang tính quyết định về bảo mật.**

2.  **`getUIMetadata(action: string, subject: string): object | null`**

    - **Mục đích:** Lấy `ui_metadata` cho một permission cụ thể.
    - **Logic:** Tìm permission (`action`, `subject`) và trả về trường `ui_metadata` của nó, hoặc `null` (hoặc `{}`) nếu không tìm thấy.

3.  **`getCurrentUser(): object | null`**

    - Trả về thông tin người dùng hiện tại từ global state.

4.  **`getUserRole(): object | null`**

    - Trả về thông tin vai trò của người dùng từ global state.

5.  **`hasFeature(featureKey: string): boolean`**
    - Kiểm tra xem một cờ tính năng có được bật cho người dùng không, dựa trên trường `features` từ global state.

---

### **6. Tích hợp Phân quyền vào Ứng dụng Next.js**

#### **6.1. Bảo vệ Route (Trang)**

- **Next.js Middleware (Khuyến nghị cho Next.js 12+):**
  - Tạo một file middleware (ví dụ: `middleware.ts` ở thư mục gốc).
  - Trong middleware, kiểm tra xem người dùng đã đăng nhập chưa. Nếu đã đăng nhập, bạn có thể (tùy chọn, nếu cần bảo vệ ở mức server) gọi một endpoint backend nhẹ để xác nhận quyền truy cập trang dựa trên `pathname` hoặc chuyển logic kiểm tra quyền cơ bản vào `PermissionService` và sử dụng nó (nếu `ui-capabilities` có thể được truy cập ở middleware).
  - Nếu không có quyền, `NextResponse.redirect()` đến trang đăng nhập hoặc trang lỗi.
- **Higher-Order Components (HOCs):**
  - Tạo một HOC (ví dụ: `withAuth`, `withPermissionCheck`) bao bọc các component trang.
  - Trong HOC, sử dụng `usePermissions().can(action_for_page, subject_for_page)` để kiểm tra.
- **Trong `getServerSideProps` hoặc `getInitialProps` (cho các trang SSR/SSG có yếu tố động):**
  - Nếu trang yêu cầu dữ liệu từ server, bạn có thể thực hiện kiểm tra quyền ở đây. Tuy nhiên, việc lấy `ui-capabilities` trong mỗi `getServerSideProps` có thể không hiệu quả. Thường thì `ui-capabilities` đã được lấy và lưu ở client.

#### **6.2. Render UI Động dựa trên Quyền**

1.  **Sử dụng `usePermissions().can()` để Ẩn/Hiện hoặc Vô hiệu hóa Elements:**

    - **Ví dụ:**

      ```jsx
      import { usePermissions } from '@/hooks/usePermissions'; // Hook của bạn

      function MyComponent({ post }) {
        const { can } = usePermissions();
        const currentUser = /* ... lấy user hiện tại ... */;

        const resourceContext = { user: currentUser, resource: post };

        return (
          <div>
            {can('update', 'Post', resourceContext) && (
              <button>Chỉnh sửa Bài viết</button>
            )}
            {!can('delete', 'Post', resourceContext) && (
              <p>Bạn không có quyền xóa bài viết này.</p>
            )}
            <button disabled={!can('publish', 'Post', resourceContext)}>
              Xuất bản
            </button>
          </div>
        );
      }
      ```

    - Áp dụng cho buttons, links, menu items, các section của trang, v.v.

2.  **Sử dụng `usePermissions().getUIMetadata()` để Cấu hình UI Động:**

    - **Ví dụ:**

      ```jsx
      import { usePermissions } from '@/hooks/usePermissions'
      import { Icon } from '@iconify/react' // Ví dụ thư viện icon

      function UserActions() {
        const { getUIMetadata, can } = usePermissions()

        const createUserMeta = getUIMetadata('create', 'User')

        if (!can('create', 'User')) return null

        return (
          <button style={{ backgroundColor: createUserMeta?.color || 'blue' }}>
            {createUserMeta?.icon && <Icon icon={createUserMeta.icon} />}
            {createUserMeta?.label || 'Tạo Người dùng'}
          </button>
        )
      }
      ```

    - Dùng để đặt nhãn, icon, màu sắc, tooltip, thứ tự hiển thị, hoặc thậm chí cấu trúc form dựa trên `ui_metadata`.

#### **6.3. Sử dụng `conditions` và `ui_metadata` một cách hiệu quả**

- **`conditions` ở Client:** Chủ yếu để cải thiện UX. Ví dụ, nếu một nút "Edit" chỉ hiển thị khi `can('update', 'Post', context)` trả về `true` (sau khi đánh giá `conditions` ở client), người dùng sẽ không thấy nút đó nếu họ không có quyền. Điều này tốt hơn là hiển thị nút rồi báo lỗi sau khi click.
- **`ui_metadata` ở Client:** Giúp giảm hardcode phía client. Thay vì client tự quyết định icon/label cho nút "Tạo User", nó lấy thông tin này từ `ui_metadata` do backend cung cấp. Điều này giúp việc thay đổi giao diện (ví dụ: đổi icon) có thể được quản lý từ backend hoặc một nơi tập trung.

---

### **7. Tương tác với API Backend**

#### **7.1. Gửi Request đã xác thực**

- Khi gọi các API backend yêu cầu xác thực, đảm bảo `access_token` được gửi kèm (thường tự động nếu dùng HTTP-only cookies, hoặc qua `Authorization: Bearer <token>` header).

#### **7.2. Xử lý Phản hồi từ API**

- **`401 Unauthorized`:**
  - Token không hợp lệ hoặc đã hết hạn.
  - Client nên tự động thử gọi `POST /auth/refresh-token`.
  - Nếu refresh thành công, thử lại request ban đầu với token mới.
  - Nếu refresh thất bại, redirect người dùng đến trang đăng nhập.
- **`403 Forbidden`:**
  - Người dùng đã được xác thực nhưng không có quyền thực hiện hành động đó.
  - Hiển thị thông báo lỗi phù hợp cho người dùng (ví dụ: "Bạn không có quyền thực hiện hành động này.").
- **Các lỗi khác:** Xử lý theo logic ứng dụng.

---

### **8. Best Practices và Lưu ý Quan trọng**

- **Backend là Nguồn Chân lý (Source of Truth):** Luôn nhớ rằng mọi kiểm tra quyền phía client chỉ nhằm mục đích cải thiện UX. Backend **PHẢI LUÔN LUÔN** thực hiện kiểm tra quyền đầy đủ và nghiêm ngặt cho mỗi request. **Không bao giờ tin tưởng vào quyết định từ client.**
- **Thư viện JSON Logic Client:** Chọn một thư viện JSON Logic ổn định và tương thích cho client (ví dụ: `json-logic-js`).
- **Thiết kế `ui_metadata`:**
  - Giữ cấu trúc `ui_metadata` đơn giản, dễ hiểu và dễ bảo trì.
  - Tránh việc `ui_metadata` quá phụ thuộc vào một thiết kế UI cụ thể, để dễ dàng thay đổi UI trong tương lai.
- **Server-Side Rendering (SSR) / Static Site Generation (SSG):**
  - Cân nhắc cách xử lý quyền hạn cho các trang được render phía server. Việc hiển thị nội dung dựa trên quyền có thể cần chiến lược riêng để tránh "flickering" hoặc lộ thông tin.
  - Đối với các trang tĩnh hoàn toàn, phân quyền thường không áp dụng.
- **Testing:**
  - Viết unit test cho `PermissionService` hoặc `usePermissions` hook của bạn.
  - Kiểm thử các component có logic hiển thị dựa trên quyền với các trạng thái quyền hạn khác nhau (mock `usePermissions`).
- **Performance:** Việc lưu trữ `ui-capabilities` trong global state giúp truy cập nhanh. Cẩn thận nếu payload này quá lớn.
- **Cập nhật Quyền hạn Động:** Nếu cần cập nhật quyền hạn của người dùng ngay lập tức mà không cần tải lại trang (ví dụ: admin thay đổi vai trò của user), bạn cần một cơ chế phức tạp hơn như WebSockets. Đối với hầu hết ứng dụng, việc cập nhật sau khi tải lại trang hoặc đăng nhập lại là đủ.

---

### **9. Tóm tắt Luồng Hoạt động Mẫu**

1.  **Khởi tạo:** Người dùng truy cập ứng dụng.
2.  **Xác thực:**
    - Nếu chưa đăng nhập, hiển thị trang đăng nhập.
    - Người dùng đăng nhập thành công.
3.  **Lấy Quyền hạn:** Client gọi `GET /auth/ui-capabilities`.
4.  **Lưu trữ:** Lưu trữ response vào global state (ví dụ: React Context).
5.  **Khởi tạo Service:** `PermissionService` hoặc `usePermissions` hook được khởi tạo với dữ liệu từ global state.
6.  **Điều hướng & Render Trang:**
    - Next.js Router điều hướng đến một trang.
    - Middleware hoặc HOC kiểm tra quyền truy cập trang bằng `usePermissions().can(action_page, subject_page)`.
    - Nếu có quyền, component trang được render.
7.  **Render Component Động:**
    - Bên trong component, sử dụng `usePermissions().can(action, subject, context)` để quyết định ẩn/hiện/vô hiệu hóa các nút, form, menu items.
    - Sử dụng `usePermissions().getUIMetadata(action, subject)` để lấy thông tin (label, icon, color) cho các element đó.
8.  **Tương tác Người dùng:**
    - Người dùng click vào một nút (ví dụ: "Lưu Thay đổi").
    - (UX) Client có thể thực hiện kiểm tra `can()` một lần nữa trước khi gửi request.
9.  **Gọi API Backend:**
    - Client gửi request (ví dụ: `PATCH /posts/123`) đến backend với `access_token`.
10. **Xử lý Backend:**
    - Backend xác thực token.
    - Backend sử dụng `PermissionGuard` để kiểm tra quyền, bao gồm cả việc đánh giá `conditions` một cách nghiêm ngặt.
11. **Phản hồi từ Backend:**
    - Nếu thành công (2xx), client cập nhật UI.
    - Nếu lỗi (401, 403, 500), client xử lý lỗi tương ứng (refresh token, hiển thị thông báo).

---

Tài liệu này cung cấp một nền tảng vững chắc để client Next.js của bạn làm việc hiệu quả với hệ thống phân quyền backend. Hãy điều chỉnh và mở rộng các khái niệm này cho phù hợp với yêu cầu cụ thể của dự án của bạn.
