import { HttpException, HttpStatus } from '@nestjs/common'

export class ApiException extends HttpException {
  constructor(
    public readonly statusCode: HttpStatus,
    public readonly code: string,
    public readonly message: string,
    public readonly details?: any,
  ) {
    super(
      {
        code,
        message,
        details,
      },
      statusCode,
    )
  }
}
