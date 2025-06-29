import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from '@nestjs/common'
import { Request, Response } from 'express'
import { I18nService, I18nValidationException } from 'nestjs-i18n'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { isObject, isString } from '../utils/type-guards.utils'

export interface StandardErrorResponse {
  success: false
  statusCode: number
  error: {
    code: string
    message: string
    details?: any
  }
  requestId?: string
}

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name)

  constructor(private readonly i18n: I18nService) {}

  async catch(exception: unknown, host: ArgumentsHost): Promise<void> {
    const ctx = host.switchToHttp()
    const request = ctx.getRequest<Request>()
    const response = ctx.getResponse<Response>()
    const lang = request.acceptsLanguages(['vi', 'en']) || 'vi'

    let statusCode: number
    let errorCode: string
    let message: string
    let details: any = null

    // Handle different types of exceptions
    if (exception instanceof ApiException) {
      statusCode = exception.getStatus()
      errorCode = exception.code
      message = await this.translate(exception.message, lang)
      details = await this.translateDetails(exception.details, lang)
    } else if (exception instanceof I18nValidationException) {
      statusCode = exception.getStatus()
      errorCode = this.getErrorCodeFromStatus(statusCode)
      message = await this.translate('global.error.VALIDATION_FAILED', lang)
      // The details (errors) are already translated by nestjs-i18n
      details = exception.errors
    } else if (exception instanceof HttpException) {
      statusCode = exception.getStatus()
      errorCode = this.getErrorCodeFromStatus(statusCode)
      const exceptionResponse = exception.getResponse()

      if (isString(exceptionResponse)) {
        message = await this.translate(exceptionResponse, lang)
      } else if (isObject(exceptionResponse)) {
        const errorObj = exceptionResponse as any
        message = await this.translate(errorObj.message || errorObj.error || 'global.error.BAD_REQUEST', lang)
        // Handle cases where validation errors are in the 'message' property
        if (Array.isArray(errorObj.message)) {
          details = await this.translateDetails(errorObj.message, lang)
          // Use a more generic message for the top level
          message = await this.translate(errorObj.error || 'global.error.VALIDATION_FAILED', lang)
        } else {
          details = await this.translateDetails(errorObj.details, lang)
        }
      } else {
        message = await this.translate('global.error.BAD_REQUEST', lang)
      }
    } else {
      // Unknown exceptions (fallback)
      statusCode = HttpStatus.INTERNAL_SERVER_ERROR
      errorCode = 'E0001'
      message = await this.translate('global.error.INTERNAL_SERVER_ERROR', lang)

      // Log unknown exceptions for debugging
      this.logger.error('Unknown exception occurred:', exception)
    }

    // Create standardized error response
    const errorResponse: StandardErrorResponse = {
      success: false,
      statusCode,
      error: {
        code: errorCode,
        message,
        ...(details && { details }),
      },
      requestId: request.headers['x-request-id'] as string,
    }

    // Log error for monitoring (exclude 4xx client errors from error logs)
    if (statusCode >= 500) {
      this.logger.error(`HTTP ${statusCode} Error - ${errorCode}: ${message}`, {
        method: request.method,
        statusCode,
        errorCode,
        userAgent: request.get('User-Agent'),
        ip: request.ip,
        details,
        stack: exception instanceof Error ? exception.stack : undefined,
      })
    } else {
      this.logger.warn(`HTTP ${statusCode} Client Error - ${errorCode}: ${message}`, {
        path: request.url,
        method: request.method,
        statusCode,
        errorCode,
      })
    }

    response.status(statusCode).json(errorResponse)
  }

  private async translate(key: string, lang: string): Promise<string> {
    if (!isString(key) || !key.includes('.')) {
      return key
    }
    try {
      return await this.i18n.translate(key, { lang })
    } catch (error) {
      this.logger.warn(`Failed to translate message key: ${key} for lang: ${lang}`, error)
      return key // Return the key itself if translation fails
    }
  }

  private async translateDetails(details: any, lang: string): Promise<any> {
    if (!details) {
      return null
    }

    if (Array.isArray(details)) {
      return Promise.all(
        details.map(async (error) => {
          if (isObject(error) && 'message' in error && isString(error.message)) {
            return {
              ...error,
              message: await this.translate(error.message, lang),
            }
          }
          return error
        }),
      )
    }

    if (isObject(details)) {
      const translatedDetails = {}
      for (const key in details) {
        if (isString(details[key])) {
          translatedDetails[key] = await this.translate(details[key], lang)
        } else {
          translatedDetails[key] = details[key]
        }
      }
      return translatedDetails
    }

    return details
  }

  private getErrorCodeFromStatus(statusCode: number): string {
    const errorCodeMap: Record<number, string> = {
      400: 'E0002', // Bad Request
      401: 'E0003', // Unauthorized
      403: 'E0004', // Forbidden
      404: 'E0005', // Not Found
      409: 'E0007', // Conflict
      422: 'E0006', // Unprocessable Entity
      429: 'E0008', // Too Many Requests
      500: 'E0001', // Internal Server Error
      502: 'E0015', // Bad Gateway
      503: 'E0009', // Service Unavailable
      504: 'E0016', // Gateway Timeout
    }

    return errorCodeMap[statusCode] || 'E0001'
  }
}
