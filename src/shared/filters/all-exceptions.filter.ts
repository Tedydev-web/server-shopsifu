import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { ZodError } from 'zod'
import { ZodValidationException, ZodSerializationException } from 'nestjs-zod'
import { ApiException } from '../exceptions/api.exception'
import { v4 as uuidv4 } from 'uuid'

interface DetailedErrorItem {
  field?: string
  message: string
  args?: Record<string, any>
}

interface ErrorResponse {
  type: string
  title: string
  status: number
  timestamp: string
  requestId: string
  errors?: DetailedErrorItem[]
}

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name)

  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost
    const ctx = host.switchToHttp()
    const request = ctx.getRequest<Request>()
    const requestId = request.headers['x-request-id']?.toString() || uuidv4()
    const timestamp = new Date().toISOString()

    let httpStatus: HttpStatus = HttpStatus.INTERNAL_SERVER_ERROR
    let errorCode: string = 'InternalServerError'
    let message: string = 'Error.Global.InternalServerError'
    let errors: DetailedErrorItem[] = []

    this.logger.error(
      `[${request.method} ${request.url}] [RequestID: ${requestId}] Exception: ${
        exception instanceof Error ? exception.message : JSON.stringify(exception)
      }`,
      exception instanceof Error ? exception.stack : undefined
    )

    if (exception instanceof ApiException) {
      httpStatus = exception.getStatus()
      errorCode = exception.errorCode
      message = exception.message
      console.log('ApiException details:', JSON.stringify(exception.details))

      errors = exception.details.map((detail) => {
        let field = detail.path || ''
        if (!field && detail.code) {
          const codeParts = detail.code.split('.')
          if (codeParts.length >= 3) {
            field = codeParts[2].toLowerCase()
          }
        }

        return {
          field,
          message: detail.code
        }
      })

      console.log('Mapped errors:', JSON.stringify(errors))
      if (errors.length === 0) {
        errors = [{ field: '', message: exception.message }]
      }
    } else if (exception instanceof ZodValidationException) {
      httpStatus = HttpStatus.UNPROCESSABLE_ENTITY
      errorCode = 'ValidationError'
      message = 'Error.Global.ValidationFailed'
      const zodError: ZodError = exception.getZodError()
      errors = zodError.errors.map((err) => ({
        field: err.path.join('.'),
        message: `Error.Validation.${err.path.join('.')}.${err.code}`
      }))
    } else if (exception instanceof ZodSerializationException) {
      httpStatus = HttpStatus.UNPROCESSABLE_ENTITY
      errorCode = 'SerializationError'
      message = 'Error.Global.SerializationFailed'
      const zodError: ZodError = exception.getZodError()
      errors = zodError.errors.map((err) => ({
        field: err.path.join('.'),
        message: `Error.Serialization.${err.path.join('.')}.${err.code}`
      }))
    } else if (exception instanceof HttpException) {
      httpStatus = exception.getStatus()
      errorCode = this.mapHttpStatusToErrorCode(httpStatus)
      const exceptionResponse = exception.getResponse()

      if (typeof exceptionResponse === 'string') {
        message = exceptionResponse
      } else if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
        const resMessage = (exceptionResponse as any).message
        if (Array.isArray(resMessage)) {
          message = 'Error.Global.ValidationFailed'
          errors = resMessage.map((detailError: any) => {
            if (typeof detailError === 'string') {
              return { field: '', message: detailError }
            }
            const i18nKey = `Error.Validation.${detailError.path}.${detailError.code}`
            return {
              field: detailError.path || '',
              message: i18nKey
            }
          })
        } else {
          message = resMessage || `Error.Global.Http.${httpStatus}`
        }
      } else {
        message = `Error.Global.Http.${httpStatus}`
      }
    } else {
      message = 'Error.Global.InternalServerError'
      errors = [{ field: '', message: 'Error.Global.InternalServerError' }]
    }

    const responseBody: ErrorResponse = {
      type: `https://api.shopsifu.live/errors/${errorCode.toLowerCase().replace(/_/g, '-')}`,
      title: this.mapHttpStatusToText(httpStatus),
      status: httpStatus,
      timestamp,
      requestId,
      errors: errors.length > 0 ? errors : [{ field: '', message }]
    }

    httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus)
  }

  private mapHttpStatusToText(status: HttpStatus): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return 'Bad Request'
      case HttpStatus.UNAUTHORIZED:
        return 'Unauthorized'
      case HttpStatus.FORBIDDEN:
        return 'Forbidden'
      case HttpStatus.NOT_FOUND:
        return 'Not Found'
      case HttpStatus.CONFLICT:
        return 'Conflict'
      case HttpStatus.UNPROCESSABLE_ENTITY:
        return 'Unprocessable Entity'
      case HttpStatus.PRECONDITION_FAILED:
        return 'Precondition Failed'
      case HttpStatus.INTERNAL_SERVER_ERROR:
        return 'Internal Server Error'
      case HttpStatus.SERVICE_UNAVAILABLE:
        return 'Service Unavailable'
      default: {
        const statusText = Object.keys(HttpStatus).find((key) => HttpStatus[key] === status)
        return statusText
          ? statusText
              .split('_')
              .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
              .join(' ')
          : 'Http Error'
      }
    }
  }

  private mapHttpStatusToErrorCode(status: HttpStatus): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return 'BadRequest'
      case HttpStatus.UNAUTHORIZED:
        return 'Unauthenticated'
      case HttpStatus.FORBIDDEN:
        return 'Forbidden'
      case HttpStatus.NOT_FOUND:
        return 'ResourceNotFound'
      case HttpStatus.CONFLICT:
        return 'ResourceConflict'
      case HttpStatus.UNPROCESSABLE_ENTITY:
        return 'ValidationError'
      case HttpStatus.PRECONDITION_FAILED:
        return 'PreconditionFailed'
      case HttpStatus.INTERNAL_SERVER_ERROR:
        return 'InternalServerError'
      case HttpStatus.SERVICE_UNAVAILABLE:
        return 'ServiceUnavailable'
      default:
        return 'UnknownError'
    }
  }
}
