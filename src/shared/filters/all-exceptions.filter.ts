import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger, Response } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { isObject } from '../utils/type-guards.utils'
import { v4 as uuidv4 } from 'uuid' // Added for requestId
import { CookieService } from 'src/shared/services/cookie.service'

/**
 * Một bộ lọc exception toàn cục để bắt tất cả các lỗi và định dạng chúng
 * thành một response JSON nhất quán theo `ErrorResponseSchema`.
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name)

  constructor(
    private readonly httpAdapterHost: HttpAdapterHost,
    private readonly i18n: I18nService,
    private readonly cookieService: CookieService
  ) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost
    const ctx = host.switchToHttp()
    const request = ctx.getRequest<Request>()
    const i18nContext = I18nContext.current()
    const response = ctx.getResponse<Response>()

    let statusCode: number
    let error: string
    let message: string
    let details: any

    if (exception instanceof ApiException) {
      // Xử lý lỗi tùy chỉnh của ứng dụng
      statusCode = exception.getStatus()
      error = exception.code
      // message trong ApiException là i18n key
      message = this.i18n.t(exception.message, {
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
        message = this.i18n.t(response, { lang: i18nContext?.lang }) ?? response
      } else if (isObject(response)) {
        error = response.error || 'VALIDATION_FAILED'
        // Đối với ZodValidationPipe, `message` là một mảng các lỗi
        const originalMessage = response.message
        message = this.i18n.t('global.error.general.validationFailed.message', { lang: i18nContext?.lang }) // Default message for validation
        details = originalMessage
      } else {
        error = 'UNHANDLED_HTTP_EXCEPTION'
        message = this.i18n.t('global.error.http.httpError.message', { lang: i18nContext?.lang })
      }
    } else {
      // Xử lý các lỗi server không mong muốn (500)
      statusCode = HttpStatus.INTERNAL_SERVER_ERROR
      error = 'INTERNAL_SERVER_ERROR'
      message = this.i18n.t('global.error.general.internalServerError.message', { lang: i18nContext?.lang })
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

    if (statusCode === 401) {
      if (response) {
        // Xóa các cookie liên quan đến đăng nhập
        this.cookieService.clearTokenCookies(response as any)

        // Xóa SLT cookie nếu có
        this.cookieService.clearSltCookie(response as any)

        // Xóa các cookie khác nếu có (trừ csrf)
        const cookies = (request as any).cookies
        if (cookies) {
          Object.keys(cookies).forEach((cookieName) => {
            if (cookieName !== '_csrf' && cookieName !== 'xsrf-token') {
              ;(response as any).clearCookie(cookieName, { path: '/' })
              this.logger.debug(`[logout] Cookie ${cookieName} đã được xóa`)
            }
          })
        }
      }
    }
    // Tạo body cho response lỗi theo format chuẩn
    const typeSuffix = error.toLowerCase().replace(/_/g, '-')
    const errorTypeUrl = `https://api.shopsifu.live/errors/${typeSuffix}`

    // Default title, can be overridden by specific error configurations
    let title = this.i18n.t(`errors.${error}.title`, {
      lang: i18nContext?.lang,
      defaultValue: this.i18n.t('global.error.general.default.title', { lang: i18nContext?.lang })
    })

    let structuredErrors: Array<{ field: string; description: string }> | undefined = undefined

    // Handle validation errors specifically to structure the 'errors' array
    if (error === 'VALIDATION_FAILED' && Array.isArray(details)) {
      title = this.i18n.t('global.error.general.validationFailed.title', { lang: i18nContext?.lang })
      structuredErrors = details.map((err: any) => {
        const field = err.path?.join('.') || err.property || 'general'
        // err.message is already the i18n key from Zod DTOs or a translated message from class-validator
        // If it's a key, i18n.t will translate it. If it's already translated, it will return as is.
        // For class-validator, messages are often pre-defined or come from default messages.
        // For Zod, we ensure DTOs provide i18n keys.
        let description = err.message
        if (i18nContext && typeof err.message === 'string' && !err.message.includes(' ')) {
          // Heuristic: check if it's a key
          description = this.i18n.t(err.message, {
            lang: i18nContext.lang,
            defaultValue: err.message,
            args: err.contexts
          })
        }
        return {
          field,
          description
        }
      })
    } else if (details && statusCode >= 500 && process.env.NODE_ENV === 'production') {
      // Do not expose details for 5xx errors in production unless it's a structured error array
      details = undefined
    }

    const responseBody = {
      type: errorTypeUrl,
      title,
      status: statusCode,
      message, // This is the main, global message for the error type
      timestamp: new Date().toISOString(),
      requestId: (request as any).id || uuidv4(), // Assumes requestId is attached by a middleware, or generates one
      errors: structuredErrors // Specific field errors for validation
      // _internal_details: process.env.NODE_ENV !== 'production' ? undefined : details // For debugging non-validation details in dev
    }
    if (process.env.NODE_ENV !== 'production' && !structuredErrors && details) {
      ;(responseBody as any).errors = details
    }

    httpAdapter.reply(ctx.getResponse(), responseBody, statusCode)
  }
}
