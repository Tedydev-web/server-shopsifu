import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { isUniqueConstraintPrismaError } from 'src/shared/helpers'

@Catch()
export class CatchEverythingFilter implements ExceptionFilter {
  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    // In certain situations `httpAdapter` might not be available in the
    // constructor method, thus we should resolve it here.
    const { httpAdapter } = this.httpAdapterHost

    const ctx = host.switchToHttp()

    let httpStatus = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR
    let message = exception instanceof HttpException ? exception.getResponse() : 'Internal Server Error'

    // Handle CSRF errors
    if (
      exception instanceof Error &&
      (exception.message.includes('CSRF') || exception.message.includes('invalid csrf token'))
    ) {
      httpStatus = HttpStatus.FORBIDDEN
      message = 'CSRF token validation failed'
    }

    if (isUniqueConstraintPrismaError(exception)) {
      httpStatus = HttpStatus.CONFLICT
      message = 'Record đã tồn tại'
    }

    const responseBody = {
      statusCode: httpStatus,
      message
    }
    httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus)
  }
}
