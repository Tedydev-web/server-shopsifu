import { HttpException, HttpStatus } from '@nestjs/common'

/**
 * Lớp Exception tùy chỉnh cho toàn bộ ứng dụng.
 * Kế thừa từ HttpException của NestJS nhưng thêm vào các trường tùy chỉnh
 * để tạo ra một cấu trúc lỗi nhất quán.
 *
 * @param statusCode - Mã trạng thái HTTP (e.g., 404, 400).
 * @param code - Một mã lỗi duy nhất, không thay đổi, máy có thể đọc (e.g., 'USER_NOT_FOUND').
 * @param message - Key của i18n để dịch ra thông báo cho người dùng.
 * @param details - (Tùy chọn) Dữ liệu bổ sung về lỗi, ví dụ như lỗi validation.
 */
export class ApiException extends HttpException {
  constructor(
    public readonly statusCode: HttpStatus,
    public readonly code: string, // Mã lỗi máy có thể đọc
    public readonly message: string, // Key i18n
    public readonly details?: any
  ) {
    // payload của exception sẽ được `AllExceptionsFilter` sử dụng
    super({ code, message, details }, statusCode)
  }
}
