# Quy ước code & kiến trúc
- Ngôn ngữ mã & JSDoc bằng tiếng Việt. Khai báo đầy đủ kiểu cho biến, tham số, giá trị trả về; tránh `any`.
- Naming: PascalCase (class), camelCase (biến/hàm), kebab-case (file/dir). Một export mỗi file.
- Hàm ngắn, single-responsibility; boolean dùng `is/has/can`.
- Tránh magic numbers, định nghĩa hằng số; dùng default params; ưu tiên bất biến; dùng `readonly` khi phù hợp.
- NestJS kiến trúc module hoá, một module cho mỗi domain; DTO xác thực bằng zod (`nestjs-zod`, `CustomZodValidationPipe`).
- Xử lý exception bằng global `HttpExceptionFilter`; interceptors: `MetricsInterceptor`, `TransformInterceptor`, `ZodSerializerInterceptor`.
- Guards: `ThrottlerBehindProxyGuard`. WebSocket dùng Redis adapter.
- I18n: tài nguyên trong `src/shared/languages` (được cấu hình copy qua build assets).
- CSDL và entities quản lý bằng Prisma; migration trong `prisma/migrations`.
