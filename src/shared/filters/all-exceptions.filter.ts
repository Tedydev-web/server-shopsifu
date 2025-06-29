import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from '@nestjs/common'
import { Request, Response } from 'express'
import { I18nService } from 'nestjs-i18n'
import { ApiException } from 'src/shared/exceptions/api.exception'

export interface StandardErrorResponse {
  success: false
  statusCode: number
  error: {
    code: string
    message: string
    details?: any
  }
  timestamp: string
  path: string
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

    let statusCode: number
    let errorCode: string
    let message: string
    let details: any = null

    // Handle different types of exceptions
    if (exception instanceof ApiException) {
      // Custom ApiException (our primary exception type)
      statusCode = exception.getStatus()
      errorCode = exception.code
      message = await this.translateMessage(exception.message, request)
      details = exception.details
    } else if (exception instanceof HttpException) {
      // Built-in NestJS HttpException
      statusCode = exception.getStatus()
      errorCode = this.getErrorCodeFromStatus(statusCode)
      const exceptionResponse = exception.getResponse()

      if (typeof exceptionResponse === 'string') {
        message = await this.translateMessage(exceptionResponse, request)
      } else if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
        const errorObj = exceptionResponse as any
        message = await this.translateMessage(errorObj.message || errorObj.error || 'global.error.BAD_REQUEST', request)
        details = errorObj.details || null
      } else {
        message = await this.translateMessage('global.error.BAD_REQUEST', request)
      }
    } else {
      // Unknown exceptions (fallback)
      statusCode = HttpStatus.INTERNAL_SERVER_ERROR
      errorCode = 'E0001'
      message = await this.translateMessage('global.error.INTERNAL_SERVER_ERROR', request)

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
      timestamp: new Date().toISOString(),
      path: request.url,
      requestId: request.headers['x-request-id'] as string,
    }

    // Log error for monitoring (exclude 4xx client errors from error logs)
    if (statusCode >= 500) {
      this.logger.error(`HTTP ${statusCode} Error - ${errorCode}: ${message}`, {
        path: request.url,
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

  private async translateMessage(messageKey: string, request: Request): Promise<string> {
    try {
      // Check if it's a translation key (contains dots)
      if (messageKey.includes('.')) {
        const lang = request.acceptsLanguages(['vi', 'en']) || 'vi'
        return await this.i18n.translate(messageKey, { lang })
      }
      // Return as-is if it's not a translation key
      return messageKey
    } catch (error) {
      this.logger.warn(`Failed to translate message: ${messageKey}`, error)
      return messageKey
    }
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
