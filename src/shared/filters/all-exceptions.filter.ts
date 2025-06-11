import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { I18nService, I18nContext, Path } from 'nestjs-i18n'
import { isObject } from '../utils/type-guards.utils'
import { CookieService } from 'src/shared/services/cookie.service'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { Response, Request } from 'express'

/**
 * Một bộ lọc exception toàn cục để bắt tất cả các lỗi và định dạng chúng
 * thành một response JSON nhất quán theo `ErrorResponseSchema`.
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name)

  constructor(
    private readonly httpAdapterHost: HttpAdapterHost,
    private readonly i18nService: I18nService<I18nTranslations>,
    private readonly cookieService: CookieService
  ) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost
    const ctx = host.switchToHttp()
    const request = ctx.getRequest<Request>()
    const response = ctx.getResponse<Response>()
    const i18nContext = I18nContext.current()
    const lang = i18nContext?.lang

    let statusCode: number
    let errorCode: string
    let details: any

    if (exception instanceof ApiException) {
      statusCode = exception.getStatus()
      errorCode = exception.code
      details = exception.details
    } else if (exception instanceof HttpException) {
      statusCode = exception.getStatus()
      const httpResponse = exception.getResponse()
      if (isObject(httpResponse)) {
        errorCode = httpResponse.error || 'VALIDATION_FAILED'
        details = httpResponse.message
      } else {
        errorCode = 'UNHANDLED_HTTP_EXCEPTION'
        details = httpResponse
      }
    } else {
      statusCode = HttpStatus.INTERNAL_SERVER_ERROR
      errorCode = 'INTERNAL_SERVER_ERROR'
      if (process.env.NODE_ENV !== 'production') {
        details = (exception as Error).message
      }
    }

    const messageKey = this.findMessageKey(errorCode)

    const message =
      exception instanceof ApiException
        ? this.i18nService.t(exception.message as any, {
            lang,
            args: isObject(details) ? details : { detail: details }
          })
        : this.i18nService.t(messageKey, { lang, defaultValue: 'An unexpected error occurred.' })

    this.logError(request, statusCode, errorCode, exception)
    this.handleAuthCookies(statusCode, request, response)

    let structuredErrors: Array<{ field: string; description: string }> | undefined

    if (errorCode === 'VALIDATION_FAILED' && Array.isArray(details)) {
      structuredErrors = details.map((err: any) => ({
        field: err.path?.join('.') || err.property || 'general',
        description: err.message
      }))
    }

    const responseBody = {
      status: statusCode,
      message,
      errors: structuredErrors
    }

    if (process.env.NODE_ENV !== 'production') {
      if (details && !structuredErrors) {
        ;(responseBody as any).message = details
      }
    } else if (statusCode >= 500 && !structuredErrors) {
      delete (responseBody as any).errors
    }

    httpAdapter.reply(ctx.getResponse(), responseBody, statusCode)
  }

  private findMessageKey(errorCode: string): Path<I18nTranslations> {
    const keys: Path<I18nTranslations>[] = [
      `http.${errorCode}.message` as any,
      `general.error.${errorCode}.message` as any,
      'general.error.default.message'
    ]
    return keys[0]
  }

  private logError(request: Request, statusCode: number, errorCode: string, exception: unknown) {
    const { method, url } = request
    const message = (exception as any).message || 'No exception message available'
    this.logger.error(`[${method} ${url}] - Status: ${statusCode} - Code: ${errorCode} - Message: ${message}`, {
      stack: (exception as Error).stack,
      exception
    })
  }

  private handleAuthCookies(statusCode: number, request: Request, response: Response) {
    if (statusCode === 401) {
      this.cookieService.clearTokenCookies(response)
      this.cookieService.clearSltCookie(response)
      const cookies = (request as any).cookies
      if (cookies) {
        Object.keys(cookies).forEach((cookieName) => {
          if (cookieName !== '_csrf' && cookieName !== 'xsrf-token') {
            response.clearCookie(cookieName, { path: '/' })
          }
        })
      }
    }
  }
}
