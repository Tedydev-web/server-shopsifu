import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { ZodError } from 'zod'
import { ZodValidationException, ZodSerializationException } from 'nestjs-zod'
import { ApiException, ErrorDetailMessage } from '../exceptions/api.exception'

interface StandardErrorResponseFormat {
  statusCode: number
  error: string // General error type code, e.g., VALIDATION_ERROR
  message: string // Primary i18n key for this error
  details: ErrorDetailMessage[] // Array of more specific error details
}

@Catch() // Catch all exceptions
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name)

  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost
    const ctx = host.switchToHttp()
    const request = ctx.getRequest<Request>()

    let httpStatus: HttpStatus = HttpStatus.INTERNAL_SERVER_ERROR
    let errorCode: string = 'INTERNAL_SERVER_ERROR'
    let messageKey: string = 'Error.Global.InternalServerError'
    let errorDetails: ErrorDetailMessage[] = []

    this.logger.error(
      `[${request.method} ${request.url}] Exception: ${exception instanceof Error ? exception.message : JSON.stringify(exception)}`,
      exception instanceof Error ? exception.stack : undefined
    )

    if (exception instanceof ApiException) {
      httpStatus = exception.getStatus()
      errorCode = exception.errorCode
      messageKey = exception.getResponse() as string // The messageKey passed to super()
      errorDetails = exception.details
    } else if (exception instanceof ZodValidationException) {
      // From createZodDto validation pipe
      httpStatus = HttpStatus.UNPROCESSABLE_ENTITY
      errorCode = 'VALIDATION_ERROR'
      messageKey = 'Error.Global.ValidationFailed'
      const zodError: ZodError = exception.getZodError()
      errorDetails = zodError.errors.map((err) => ({
        path: err.path.join('.'),
        code: `Error.Validation.${err.path.join('.')}.${err.code}`, // Construct a more specific i18n key
        args: { message: err.message } // Pass Zod's original message as args for fallback
      }))
    } else if (exception instanceof ZodSerializationException) {
      // From ZodSerializerInterceptor
      httpStatus = HttpStatus.UNPROCESSABLE_ENTITY // Or 500, as it's a server-side serialization issue
      errorCode = 'SERIALIZATION_ERROR'
      messageKey = 'Error.Global.SerializationFailed'
      const zodError: ZodError = exception.getZodError()
      errorDetails = zodError.errors.map((err) => ({
        path: err.path.join('.'),
        code: `Error.Serialization.${err.path.join('.')}.${err.code}`,
        args: { message: err.message }
      }))
    } else if (exception instanceof HttpException) {
      httpStatus = exception.getStatus()
      const response = exception.getResponse()
      errorCode = this.mapHttpStatusToErrorCode(httpStatus)

      if (typeof response === 'string') {
        messageKey = response // Assume the string is the i18n key
      } else if (typeof response === 'object' && response !== null && 'message' in response) {
        // For NestJS default errors like { statusCode: 400, message: 'Bad Request', error: 'Bad Request' }
        // Or UnprocessableEntityException with array of messages
        if (Array.isArray((response as any).message)) {
          messageKey = 'Error.Global.ValidationFailed' // General key for multiple validation issues
          errorDetails = ((response as any).message as Array<string | { message: string; path?: string }>).map(
            (detailError: any) => {
              if (typeof detailError === 'string') return { code: detailError }
              // If your UnprocessableEntityException provides { message: 'key', path: 'field'}
              return { code: detailError.message, path: detailError.path }
            }
          )
        } else {
          messageKey = (response as any).message || messageKey
        }
      } else {
        messageKey = `Error.Global.Http.${httpStatus}`
      }
    } else {
      // For non-HttpException errors, keep the defaults (500, INTERNAL_SERVER_ERROR, etc.)
      // No specific details unless we can parse the error further
      errorDetails = [{ code: 'Error.Global.UnknownError' }]
    }

    const responseBody: StandardErrorResponseFormat = {
      statusCode: httpStatus,
      error: errorCode,
      message: messageKey,
      details: errorDetails.length > 0 ? errorDetails : [{ code: messageKey }] // Ensure details always has at least the main messageKey if empty
    }

    httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus)
  }

  private mapHttpStatusToErrorCode(status: HttpStatus): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return 'BAD_REQUEST'
      case HttpStatus.UNAUTHORIZED:
        return 'UNAUTHENTICATED'
      case HttpStatus.FORBIDDEN:
        return 'FORBIDDEN'
      case HttpStatus.NOT_FOUND:
        return 'NOT_FOUND'
      case HttpStatus.UNPROCESSABLE_ENTITY:
        return 'VALIDATION_ERROR'
      case HttpStatus.INTERNAL_SERVER_ERROR:
        return 'INTERNAL_SERVER_ERROR'
      case HttpStatus.SERVICE_UNAVAILABLE:
        return 'SERVICE_UNAVAILABLE'
      case HttpStatus.CONFLICT:
        return 'CONFLICT_ERROR'
      // Add more mappings as needed
      default:
        return 'UNKNOWN_HTTP_ERROR'
    }
  }
}
