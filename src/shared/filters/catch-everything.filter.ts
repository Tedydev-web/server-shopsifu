import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { isUniqueConstraintPrismaError } from 'src/shared/helpers'

@Catch()
export class CatchEverythingFilter implements ExceptionFilter {
  private readonly logger = new Logger(CatchEverythingFilter.name)

  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    // In certain situations `httpAdapter` might not be available in the
    // constructor method, thus we should resolve it here.
    const { httpAdapter } = this.httpAdapterHost

    const ctx = host.switchToHttp()

    let httpStatus = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR
    let message: any = exception instanceof HttpException ? exception.getResponse() : 'Internal Server Error'

    // Ghi log lỗi
    this.logger.error(exception instanceof Error ? exception.stack : exception)

    // Chuẩn hóa định dạng lỗi
    if (isUniqueConstraintPrismaError(exception)) {
      httpStatus = HttpStatus.CONFLICT
      message = [
        {
          message: 'Error.RecordAlreadyExists',
          path: 'record'
        }
      ]
    }

    // Đảm bảo định dạng phản hồi nhất quán
    if (typeof message === 'string') {
      message = [
        {
          message,
          path: 'general'
        }
      ]
    }

    const responseBody = {
      statusCode: httpStatus,
      message
    }

    httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus)
  }
}
