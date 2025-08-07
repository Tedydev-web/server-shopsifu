# Quy tắc code style và conventions

## TypeScript Guidelines
- Sử dụng tiếng Việt cho tất cả code và documentation
- Luôn khai báo type cho mỗi biến và function
- Tránh sử dụng `any`
- Tạo các types cần thiết
- Sử dụng JSDoc để document public classes và methods
- Không để dòng trống trong function
- Một export per file

## Naming Conventions
- **Classes**: PascalCase
- **Variables, functions, methods**: camelCase
- **Files và directories**: kebab-case
- **Environment variables**: UPPERCASE
- **Boolean variables**: Sử dụng động từ (isLoading, hasError, canDelete)
- **Functions**: Bắt đầu bằng động từ, nếu trả về boolean dùng isX/hasX/canX

## Function Guidelines
- Viết functions ngắn với mục đích đơn lẻ (< 20 instructions)
- Tránh nested blocks bằng early returns
- Sử dụng higher-order functions (map, filter, reduce)
- Sử dụng arrow functions cho simple functions (< 3 instructions)
- Sử dụng default parameter values thay vì check null/undefined
- Giảm parameters bằng cách sử dụng object (RO-RO pattern)

## Class Guidelines
- Tuân thủ SOLID principles
- Ưu tiên composition over inheritance
- Khai báo interfaces để định nghĩa contracts
- Viết classes nhỏ với mục đích đơn lẻ (< 200 instructions, < 10 public methods)

## NestJS Architecture
- Sử dụng modular architecture
- Encapsulate API trong modules
- Một module per main domain/route
- Một controller cho route chính
- Models folder với data types
- DTOs validated với class-validator
- Services với business logic và persistence
- Entities với Prisma cho data persistence

## Exception Handling
- Sử dụng exceptions cho errors không mong đợi
- Catch exceptions để fix expected problems hoặc add context
- Sử dụng global handler cho các trường hợp khác

## Testing
- Tuân thủ Arrange-Act-Assert convention
- Đặt tên test variables rõ ràng (inputX, mockX, actualX, expectedX)
- Viết unit tests cho mỗi public function
- Sử dụng test doubles để simulate dependencies
- Viết acceptance tests cho mỗi module
- Tuân thủ Given-When-Then convention