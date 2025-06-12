import { HttpException, HttpStatus } from '@nestjs/common'

export class ApiException extends HttpException {
  constructor(
    public readonly statusCode: HttpStatus,
    public readonly code: string, // Mã lỗi máy có thể đọc
    public readonly message: string, // Key i18n
    public readonly details?: any
  ) {
    super({ code, message, details }, statusCode)
  }
}
