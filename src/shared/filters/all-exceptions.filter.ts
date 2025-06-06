import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { isObject } from '../utils/type-guards.utils'

/**
 * Một bộ lọc exception toàn cục để bắt tất cả các lỗi và định dạng chúng
 * thành một response JSON nhất quán theo `ErrorResponseSchema`.
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name)

  constructor(
    private readonly httpAdapterHost: HttpAdapterHost,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost
    const ctx = host.switchToHttp()
    const request = ctx.getRequest<Request>()
    const i18nContext = I18nContext.current<I18nTranslations>(host)

    let statusCode: number
    let error: string
    let message: string
    let details: any

    if (exception instanceof ApiException) {
      // Xử lý lỗi tùy chỉnh của ứng dụng
      statusCode = exception.getStatus()
      error = exception.code
      // message trong ApiException là i18n key
      message = this.i18n.t(exception.message as any, {
        lang: i18nContext?.lang,
        args: isObject(exception.details) ? exception.details : { detail: exception.details }
      })
      details = exception.details
    } else if (exception instanceof HttpException) {
      // Xử lý các lỗi HTTP khác (ví dụ: từ các guard, pipe của NestJS)
      statusCode = exception.getStatus()
      const response = exception.getResponse()

      if (typeof response === 'string') {
        error = 'HTTP_EXCEPTION'
        message = this.i18n.t(response as any, { lang: i18nContext?.lang }) ?? response
      } else if (isObject(response)) {
        error = response.error || 'VALIDATION_FAILED'
        // Đối với ZodValidationPipe, `message` là một mảng các lỗi
        const originalMessage = response.message
        message = this.i18n.t(`global.error.general.validationFailed` as any, { lang: i18nContext?.lang })
        details = originalMessage
      } else {
        error = 'UNHANDLED_HTTP_EXCEPTION'
        message = this.i18n.t('global.error.http.httpError' as any, { lang: i18nContext?.lang })
      }
    } else {
      // Xử lý các lỗi server không mong muốn (500)
      statusCode = HttpStatus.INTERNAL_SERVER_ERROR
      error = 'INTERNAL_SERVER_ERROR'
      message = this.i18n.t('global.error.general.internalServerError' as any, { lang: i18nContext?.lang })
      // Chỉ hiển thị chi tiết lỗi ở môi trường dev
      if (process.env.NODE_ENV !== 'production') {
        details = (exception as Error).message
      }
    }

    this.logger.error(
      `[${request.method} ${request.url}] - Status: ${statusCode} - Error: ${error} - Message: ${
        (exception as any).message
      }`,
      (exception as Error).stack
    )

    // Tạo body cho response lỗi theo format chuẩn
    const responseBody = {
      success: false,
      statusCode,
      error,
      message,
      details
    }

    httpAdapter.reply(ctx.getResponse(), responseBody, statusCode)
  }
}
