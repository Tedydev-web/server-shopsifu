import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { ZodError } from 'zod'
import { ZodValidationException, ZodSerializationException } from 'nestjs-zod'
import { ApiException, ErrorDetailMessage } from '../exceptions/api.exception'
import { v4 as uuidv4 } from 'uuid'

interface DetailedErrorItem {
  field?: string
  description: string
  args?: Record<string, any>
}

interface NewErrorResponse {
  type: string
  title: string
  status: number
  description?: string
  timestamp: string
  requestId?: string
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
    const response = ctx.getResponse()

    let httpStatus: HttpStatus = HttpStatus.INTERNAL_SERVER_ERROR
    let errorCode: string = 'INTERNAL_SERVER_ERROR'
    let descriptionKey: string = 'Error.Global.InternalServerError'
    let processedErrorDetails: DetailedErrorItem[] = []

    this.logger.error(
      `[${request.method} ${request.url}] Exception: ${exception instanceof Error ? exception.message : JSON.stringify(exception)}`,
      exception instanceof Error ? exception.stack : undefined
    )

    if (exception instanceof ApiException) {
      httpStatus = exception.getStatus()
      errorCode = exception.errorCode
      descriptionKey = exception.getResponse() as string
      processedErrorDetails = (exception.details || []).map((detail) => ({
        field: detail.path,
        description: detail.code,
        ...(detail.args && { args: detail.args })
      }))
    } else if (exception instanceof ZodValidationException) {
      httpStatus = HttpStatus.UNPROCESSABLE_ENTITY
      errorCode = 'VALIDATION_ERROR'
      descriptionKey = 'Error.Global.ValidationFailed'
      const zodError: ZodError = exception.getZodError()
      processedErrorDetails = zodError.errors.map((err) => {
        const i18nKeyCode = `Error.Validation.${err.path.join('.')}.${err.code}`
        return {
          field: err.path.join('.'),
          description: i18nKeyCode
        }
      })
    } else if (exception instanceof ZodSerializationException) {
      httpStatus = HttpStatus.UNPROCESSABLE_ENTITY
      errorCode = 'SERIALIZATION_ERROR'
      descriptionKey = 'Error.Global.SerializationFailed'
      const zodError: ZodError = exception.getZodError()
      processedErrorDetails = zodError.errors.map((err) => {
        const i18nKeyCode = `Error.Serialization.${err.path.join('.')}.${err.code}`
        return {
          field: err.path.join('.'),
          description: i18nKeyCode
        }
      })
    } else if (exception instanceof HttpException) {
      httpStatus = exception.getStatus()
      const exceptionResponse = exception.getResponse()
      errorCode = this.mapHttpStatusToErrorCode(httpStatus)

      if (typeof exceptionResponse === 'string') {
        descriptionKey = exceptionResponse
      } else if (
        typeof exceptionResponse === 'object' &&
        exceptionResponse !== null &&
        'message' in exceptionResponse
      ) {
        const resMessage = (exceptionResponse as any).message
        if (Array.isArray(resMessage)) {
          descriptionKey = 'Error.Global.ValidationFailed'
          processedErrorDetails = resMessage.map((detailError: any) => {
            if (typeof detailError === 'string') {
              return { description: detailError }
            }
            const i18nKeyForDetail = `Error.Validation.${detailError.path}.${detailError.code}`
            return {
              field: detailError.path,
              description: i18nKeyForDetail
            }
          })
        } else {
          descriptionKey = resMessage || `Error.Global.Http.${httpStatus}`
        }
      } else {
        descriptionKey = `Error.Global.Http.${httpStatus}`
      }
    } else {
      processedErrorDetails = [{ description: descriptionKey }]
    }

    const timestamp = new Date().toISOString()
    const reqId = request.headers['x-request-id'] || uuidv4()
    const title = this.mapHttpStatusToText(httpStatus)
    const typeUrlErrorSegment = errorCode.toLowerCase().replace(/_/g, '-')

    const responseBody: NewErrorResponse = {
      type: `https://api.shopsifu.live/errors/${typeUrlErrorSegment}`,
      title,
      status: httpStatus,
      timestamp,
      requestId: reqId
    }

    // Add errors if there are field-specific details
    if (processedErrorDetails.length > 0) {
      responseBody.errors = processedErrorDetails
    } else {
      // Add root-level description for non-field-specific errors
      responseBody.description = descriptionKey
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
      default:
        return 'UNKNOWN_HTTP_ERROR'
    }
  }
}
