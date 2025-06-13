import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { I18nService, I18nContext, Path } from 'nestjs-i18n'
import { CookieService } from 'src/shared/services/cookie.service'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { Response, Request } from 'express'
import { ZodError } from 'zod'

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
    } else if (exception instanceof ZodError) {
      statusCode = HttpStatus.UNPROCESSABLE_ENTITY
      errorCode = 'VALIDATION_FAILED'
      const httpResponse = exception.flatten()
      // Ensure details are captured correctly from Zod's flattened error structure
      details = {
        formErrors: httpResponse.formErrors,
        fieldErrors: httpResponse.fieldErrors
      }
    } else if (exception instanceof HttpException) {
      statusCode = exception.getStatus()
      const httpResponse = exception.getResponse()
      if (typeof httpResponse === 'object' && httpResponse !== null) {
        errorCode = (httpResponse as any).code || 'UNKNOWN_ERROR'
        details = (httpResponse as any).details || (httpResponse as any).message
      } else {
        errorCode = 'UNKNOWN_ERROR'
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
            args: details
          })
        : this.i18nService.t(messageKey, { lang, defaultValue: 'An unexpected error occurred.' })

    this.logError(request, statusCode, errorCode, exception)
    this.handleAuthCookies(statusCode, request, response)

    let structuredErrors: Array<{ field: string; description: string }> | undefined

    // List of login-related error codes that should not return field details
    const loginErrorCodes = ['AUTH_INVALID_LOGIN_CREDENTIALS', 'AUTH_INVALID_EMAIL_FORMAT', 'AUTH_PASSWORD_TOO_SHORT']

    // Handle different types of validation errors
    if (errorCode === 'VALIDATION_FAILED' && Array.isArray(details)) {
      // Check if this is from login endpoint - don't return field details for login validation
      const isLoginEndpoint = request.url?.includes('/auth/login')
      if (isLoginEndpoint) {
        // For login validation, don't return field-specific errors
        structuredErrors = undefined
      } else {
        structuredErrors = details.map((err: any) => ({
          field: err.path?.join('.') || err.property || 'general',
          description: err.message
        }))
      }
    } else if (exception instanceof ApiException && details?.field && !loginErrorCodes.includes(errorCode)) {
      // Handle single field errors from ApiException, but exclude login-related errors
      structuredErrors = [
        {
          field: details.field,
          description: typeof message === 'string' ? message : 'Validation error'
        }
      ]
    }

    const responseBody: any = {
      status: statusCode,
      message,
      errors: structuredErrors
    }

    // Add canRetry flag for verification errors
    if (details?.canRetry !== undefined) {
      responseBody.canRetry = details.canRetry
    }

    // Only add details for debugging in non-production, but preserve the translated message
    if (process.env.NODE_ENV !== 'production') {
      if (details && !structuredErrors) {
        responseBody.details = details
      }
    } else if (statusCode >= 500 && !structuredErrors) {
      delete responseBody.errors
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
    // Chỉ xóa auth cookies khi thực sự là lỗi authentication nghiêm trọng
    if (statusCode === 401) {
      const url = request.url
      const isVerificationEndpoint =
        url?.includes('/auth/2fa/verify') ||
        url?.includes('/auth/otp/verify') ||
        url?.includes('/auth/2fa/setup') ||
        url?.includes('/auth/2fa/confirm-setup')

      // Nếu là endpoint verification, chỉ xóa access/refresh tokens, giữ lại SLT
      if (isVerificationEndpoint) {
        this.cookieService.clearTokenCookies(response)
        return
      }

      // Các trường hợp khác: xóa tất cả auth cookies
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
