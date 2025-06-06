import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, LoggerService, Inject } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { Request, Response } from 'express'
import { I18nService, I18nValidationException, I18nContext } from 'nestjs-i18n'
import { ApiException, ErrorDetailMessage } from '../exceptions/api.exception'
import { ConfigService } from '@nestjs/config'
import { I18nTranslations, I18nPath } from '../../generated/i18n.generated'
import { v4 as uuidv4 } from 'uuid'
import { LOGGER_SERVICE } from '../constants/injection.tokens'

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  constructor(
    private readonly httpAdapterHost: HttpAdapterHost,
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(LOGGER_SERVICE) private readonly logger: LoggerService,
    private readonly configService: ConfigService
  ) {}

  async catch(exception: unknown, host: ArgumentsHost): Promise<void> {
    const { httpAdapter } = this.httpAdapterHost
    const ctx = host.switchToHttp()
    const response = ctx.getResponse<Response>()
    const request = ctx.getRequest<Request>()
    const lang = I18nContext.current()?.lang || this.configService.get('app.fallbackLanguage') || 'en'

    let httpStatus = HttpStatus.INTERNAL_SERVER_ERROR
    let messageKeyForMainError: string = 'global.error.http.internalServerError' // Default i18n key
    let errors: Array<{ field: string; message: string | Record<string, any> }> = []
    let errorCode: string | undefined = 'INTERNAL_SERVER_ERROR' // Default errorCode for server errors
    const errorId = uuidv4()

    if (exception instanceof ApiException) {
      httpStatus = exception.getStatus()
      messageKeyForMainError = exception.message // This is an i18n key
      errorCode = exception.errorCode // Specific error code like INVALID_ACCESS_TOKEN
      if (exception.details && Array.isArray(exception.details)) {
        errors = exception.details.map((detail: ErrorDetailMessage) => ({
          field: detail.path || 'detail',
          message: detail.code // This is an i18n key for the field error
        }))
      }
    } else if (exception instanceof I18nValidationException) {
      httpStatus = exception.getStatus()
      messageKeyForMainError = 'global.error.general.validationFailed' // i18n key for main message
      errorCode = 'VALIDATION_ERROR'
      errors = exception.errors.map((err) => ({
        // Messages here are usually raw
        field: err.property,
        message: err.constraints ? Object.values(err.constraints).join(', ') : 'Validation error'
      }))
    } else if (exception instanceof HttpException) {
      httpStatus = exception.getStatus()
      const responseData = exception.getResponse()
      if (typeof responseData === 'string') {
        messageKeyForMainError = responseData // Can be an i18n key or raw message
        errorCode = HttpStatus[httpStatus] || exception.constructor.name
      } else if (typeof responseData === 'object' && responseData !== null) {
        const errorObj = responseData as Record<string, any>
        messageKeyForMainError = errorObj.i18nKey || errorObj.message || messageKeyForMainError
        errorCode = errorObj.errorCode || errorObj.error || HttpStatus[httpStatus] || exception.constructor.name

        if (Array.isArray(errorObj.errors)) {
          // Standard class-validator errors
          errors = errorObj.errors.map((err: any) => ({
            field: err.property || err.field || 'unknown',
            message: err.constraints ? Object.values(err.constraints).join(', ') : err.message || 'Validation error'
          }))
        } else if (errorObj.message && typeof errorObj.message === 'object' && !Array.isArray(errorObj.message)) {
          if (Array.isArray(errorObj.message.issues)) {
            // Zod errors
            errors = errorObj.message.issues.map((issue: any) => ({
              field: issue.path.join('.'),
              message: issue.message // Raw Zod message
            }))
            messageKeyForMainError = errorObj.i18nKey || 'global.error.general.validationFailed'
          } else if (typeof errorObj.message === 'string') {
            errors = [{ field: 'general', message: errorObj.message }]
          }
        } else if (typeof errorObj.message === 'string') {
          errors = [{ field: 'general', message: errorObj.message }]
        }
      }
    } else if (exception instanceof Error) {
      // httpStatus and messageKeyForMainError remain default (INTERNAL_SERVER_ERROR)
      errorCode = exception.name === 'Error' ? 'UNHANDLED_ERROR' : exception.name // e.g. TypeError, RangeError
      errors = [{ field: 'server', message: exception.message }] // Raw error message
      if (this.logger && typeof this.logger.error === 'function') {
        this.logger.error('Unhandled Exception: ' + exception.message, exception.stack || '', 'AllExceptionsFilter')
      }
    } else {
      // httpStatus and messageKeyForMainError remain default
      errorCode = 'UNKNOWN_ERROR'
      errors = [{ field: 'server', message: 'An unexpected error occurred' }]
      if (this.logger && typeof this.logger.error === 'function') {
        this.logger.error('Unhandled exception of unknown type', exception as any, 'AllExceptionsFilter')
      }
    }

    const mainTranslationResult = await Promise.resolve(
      this.i18nService.t(messageKeyForMainError as I18nPath, {
        lang,
        args: { errorId }
      })
    ).catch(() => messageKeyForMainError)

    const translatedMainMessage =
      typeof mainTranslationResult === 'string' ? mainTranslationResult : messageKeyForMainError

    const translatedErrors = await Promise.all(
      errors.map(async (err) => {
        if (typeof err.message === 'string') {
          const isKeyLike = /^[a-zA-Z0-9_.-]+(\.[a-zA-Z0-9_.-]+)*$/.test(err.message)
          if (isKeyLike) {
            const errMessageTranslationResult = await Promise.resolve(
              this.i18nService.t(err.message as I18nPath, {
                lang
              })
            ).catch(() => err.message)
            return {
              ...err,
              message: typeof errMessageTranslationResult === 'string' ? errMessageTranslationResult : err.message
            }
          }
        }
        return err
      })
    )

    const errorResponse = {
      success: false,
      statusCode: httpStatus,
      errorId,
      message: translatedMainMessage,
      errors: translatedErrors.length > 0 ? translatedErrors : undefined,
      errorCode,
      timestamp: new Date().toISOString(),
      path: request.url
    }

    const requestUrl = request.url
    const configApiUrl = this.configService.get<string>('API_URL')
    const errorBaseUrl = this.configService.get<string>('NODE_ENV') === 'production' ? configApiUrl : configApiUrl
    const fullErrorUrl = errorBaseUrl ? errorBaseUrl + requestUrl : requestUrl
    const logMessage = 'HTTP Error: ' + httpStatus + ' ' + translatedMainMessage + ' at ' + fullErrorUrl

    if (this.logger && typeof this.logger.error === 'function') {
      this.logger.error(
        {
          message: logMessage,
          errorId,
          statusCode: httpStatus,
          errorCode,
          path: request.url,
          method: request.method,
          ip: request.ip,
          userAgent: request.headers['user-agent'],
          exceptionStack: exception instanceof Error ? exception.stack || '' : 'N/A',
          errorDetails: translatedErrors
        },
        exception instanceof Error ? exception.stack || '' : '',
        'AllExceptionsFilter'
      )
    }

    httpAdapter.reply(response, errorResponse, httpStatus)
  }
}
