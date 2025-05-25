import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common'
import { HttpAdapterHost } from '@nestjs/core'
import { ZodError } from 'zod'
import { ZodValidationException, ZodSerializationException } from 'nestjs-zod'
import { I18nService, I18nContext, I18nValidationException } from 'nestjs-i18n'
import { ApiException } from '../exceptions/api.exception'
import { v4 as uuidv4 } from 'uuid'
import envConfig from '../config'

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

  constructor(
    private readonly httpAdapterHost: HttpAdapterHost,
    private readonly i18nService: I18nService
  ) {
    this.logger.log('AllExceptionsFilter initialized with i18n support')
  }

  private async _translateOrDefault(
    key: any,
    lang: string | undefined,
    args?: any,
    defaultMessageKey: string = 'Error.Global.Unknown'
  ): Promise<string> {
    // Nếu key không phải string hoặc rỗng, sử dụng defaultMessageKey
    if (typeof key !== 'string' || !key) {
      this.logger.debug(`Invalid translation key: ${key}, using default key: ${defaultMessageKey}`)
      key = defaultMessageKey
    }

    // Chuyển key sang string an toàn
    const translationKey = String(key)

    try {
      // Thử dịch với key đã cho
      this.logger.debug(`Attempting to translate key: '${translationKey}' with language: ${lang || 'default'}`)
      const translatedMessage = await this.i18nService.translate(translationKey, {
        lang,
        args
      })

      // Nếu kết quả dịch trả về giống hệt key gốc (tức là không có bản dịch)
      // và key đó không phải là defaultMessageKey, thử dịch defaultMessageKey
      if (translatedMessage === translationKey && translationKey !== defaultMessageKey) {
        this.logger.debug(`No translation found for '${translationKey}', falling back to '${defaultMessageKey}'`)
        try {
          const defaultTranslation = await this.i18nService.translate(defaultMessageKey, { lang })
          return String(defaultTranslation)
        } catch (defaultError) {
          this.logger.warn(`Failed to translate default key '${defaultMessageKey}': ${defaultError.message}`)
          return defaultMessageKey
        }
      }

      return String(translatedMessage)
    } catch (error) {
      this.logger.warn(`Translation failed for key: '${translationKey}', error: ${error.message}`)

      // Nếu dịch thất bại và key khác defaultMessageKey, thử dịch defaultMessageKey
      if (translationKey !== defaultMessageKey) {
        try {
          const defaultTranslation = await this.i18nService.translate(defaultMessageKey, { lang })
          return String(defaultTranslation)
        } catch (defaultError) {
          this.logger.error(`Failed to translate both original key and default key: ${defaultError.message}`)
        }
      }

      // Fallback cuối cùng: trả về defaultMessageKey dưới dạng string
      return defaultMessageKey
    }
  }

  async catch(exception: unknown, host: ArgumentsHost): Promise<void> {
    const { httpAdapter } = this.httpAdapterHost
    const ctx = host.switchToHttp()
    const request = ctx.getRequest<Request>()

    // Lấy ngôn ngữ từ I18nContext hoặc từ Accept-Language header
    let lang = I18nContext.current(host)?.lang
    if (!lang) {
      const acceptLanguage = request.headers['accept-language']
      if (typeof acceptLanguage === 'string') {
        lang = acceptLanguage.split(',')[0].trim()
      }
    }
    this.logger.debug(`Using language: ${lang || 'default'} for request ${request.url}`)

    const requestId = request.headers['x-request-id']?.toString() || uuidv4()
    const timestamp = new Date().toISOString()

    let httpStatus: HttpStatus = HttpStatus.INTERNAL_SERVER_ERROR
    let errorCode: string = 'InternalServerError'
    let messageKeyForMainError: string = 'Error.Global.InternalServerError'
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
      messageKeyForMainError = String(errorCode)

      if (exception.details && exception.details.length > 0) {
        errors = await Promise.all(
          exception.details.map(async (detail) => ({
            field: detail.path || '',
            message: await this._translateOrDefault(detail.code, lang, detail.args)
          }))
        )
      } else {
        // Nếu không có details, lỗi chính là messageKeyForMainError
        // errors sẽ được tạo ở dưới từ message chính
      }
    } else if (exception instanceof ZodValidationException || exception instanceof I18nValidationException) {
      httpStatus = HttpStatus.UNPROCESSABLE_ENTITY
      errorCode = 'ValidationError'
      messageKeyForMainError = 'Error.Global.ValidationFailed'

      if (exception instanceof ZodValidationException) {
        const zodError: ZodError = exception.getZodError()
        errors = zodError.errors.map((err) => ({
          field: err.path.join('.'),
          message: String(err.message) // Zod messages thường không phải i18n keys, giữ nguyên
        }))
      } else {
        // I18nValidationException
        errors = exception.errors.map((err) => ({
          field: err.property,
          // Messages từ I18nValidationException đã được dịch bởi nestjs-i18n theo decorators
          message: Object.values(err.constraints || {}).join(', ')
        }))
      }
    } else if (exception instanceof ZodSerializationException) {
      httpStatus = HttpStatus.UNPROCESSABLE_ENTITY
      errorCode = 'SerializationError'
      messageKeyForMainError = 'Error.Global.SerializationFailed'
      const zodError: ZodError = exception.getZodError()
      errors = zodError.errors.map((err) => ({
        field: err.path.join('.'),
        message: String(err.message) // Zod messages thường không phải i18n keys
      }))
    } else if (exception instanceof HttpException) {
      httpStatus = exception.getStatus()
      errorCode = this.mapHttpStatusToErrorCode(httpStatus)
      const exceptionResponse = exception.getResponse()
      messageKeyForMainError = `Error.Global.Http.${httpStatus}` // Default key for HttpExceptions

      if (typeof exceptionResponse === 'string') {
        // Xem exceptionResponse có phải là i18n key không
        messageKeyForMainError = exceptionResponse
      } else if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
        const resMessageContent = (exceptionResponse as any).message
        if (Array.isArray(resMessageContent)) {
          messageKeyForMainError = 'Error.Global.ValidationFailed' // Message chung cho lỗi validation
          errors = await Promise.all(
            resMessageContent.map(async (detailError: any) => {
              let msgKeyOrText: string
              if (typeof detailError === 'string') {
                msgKeyOrText = detailError
              } else {
                const firstConstraintMessage = detailError.constraints
                  ? (Object.values(detailError.constraints)[0] as string)
                  : 'Error.Global.Unknown'
                msgKeyOrText = firstConstraintMessage
              }
              return {
                field: typeof detailError === 'string' ? '' : detailError.property || detailError.path || '',
                message: await this._translateOrDefault(msgKeyOrText, lang)
              }
            })
          )
        } else if (resMessageContent) {
          messageKeyForMainError = String(resMessageContent) // Message từ response của HttpException
        }
      }
    } else {
      // Giữ nguyên messageKeyForMainError = 'Error.Global.InternalServerError' đã đặt ở trên
    }

    // Dịch message chính cho response
    const translatedMainMessage = await this._translateOrDefault(messageKeyForMainError, lang)

    // Nếu errors rỗng và có message chính, tạo errors từ message chính
    if (errors.length === 0) {
      errors = [{ field: '', message: translatedMainMessage }]
    }

    const errorBaseUrl = envConfig.NODE_ENV === 'production' ? envConfig.API_HOST_URL : envConfig.API_LOCAL_URL

    const responseBody: ErrorResponse = {
      type: `${errorBaseUrl}/errors/${errorCode.toLowerCase().replace(/_/g, '-')}`,
      title: await this.mapHttpStatusToText(httpStatus, lang), // Await the translated title
      status: httpStatus,
      timestamp,
      requestId,
      // Nếu errors chỉ có một phần tử và message của nó giống hệt translatedMainMessage thì không cần trường errors riêng
      // Hoặc luôn hiển thị errors nếu nó có nội dung
      errors:
        errors.length > 0 &&
        (errors.length > 1 || errors[0].message !== translatedMainMessage || errors[0].field !== '')
          ? errors
          : [{ field: '', message: translatedMainMessage }] // Đảm bảo luôn có ít nhất một lỗi hiển thị message chính
    }
    // Đảm bảo message trong errors không bị trùng lặp nếu chỉ có 1 lỗi và nó lỗi chung
    if (
      responseBody.errors &&
      responseBody.errors.length === 1 &&
      responseBody.errors[0].message === translatedMainMessage &&
      responseBody.errors[0].field === ''
    ) {
      // Trong trường hợp này, có thể chọn không trả về mảng errors nếu message chung đã đủ
      // Hoặc giữ nguyên để cấu trúc nhất quán
    }

    httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus)
  }

  private async mapHttpStatusToText(status: HttpStatus, lang?: string): Promise<string> {
    let titleKey = 'HttpStatus.Title.HttpError' // Default title key
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        titleKey = 'HttpStatus.Title.BadRequest'
        break
      case HttpStatus.UNAUTHORIZED:
        titleKey = 'HttpStatus.Title.Unauthorized'
        break
      case HttpStatus.FORBIDDEN:
        titleKey = 'HttpStatus.Title.Forbidden'
        break
      case HttpStatus.NOT_FOUND:
        titleKey = 'HttpStatus.Title.NotFound'
        break
      case HttpStatus.CONFLICT:
        titleKey = 'HttpStatus.Title.Conflict'
        break
      case HttpStatus.UNPROCESSABLE_ENTITY:
        titleKey = 'HttpStatus.Title.UnprocessableEntity'
        break
      case HttpStatus.PRECONDITION_FAILED:
        titleKey = 'HttpStatus.Title.PreconditionFailed'
        break
      case HttpStatus.INTERNAL_SERVER_ERROR:
        titleKey = 'HttpStatus.Title.InternalServerError'
        break
      case HttpStatus.SERVICE_UNAVAILABLE:
        titleKey = 'HttpStatus.Title.ServiceUnavailable'
        break
      default: {
        // For other statuses, fallback to HttpError title
        titleKey = 'HttpStatus.Title.HttpError'
      }
    }

    try {
      // Thử dịch key với ngôn ngữ hiện tại
      const translatedTitle = await this.i18nService.translate(titleKey, { lang })

      // Kiểm tra nếu kết quả dịch là key gốc, thì trả về fallback text tương ứng
      if (translatedTitle === titleKey) {
        this.logger.debug(`Translation for '${titleKey}' not found, using fallback text`)
        return this.getFallbackTitleText(status)
      }

      return String(translatedTitle)
    } catch (error) {
      this.logger.warn(`Failed to translate title key '${titleKey}': ${error.message}`)
      // Trả về text fallback nếu dịch thất bại
      return this.getFallbackTitleText(status)
    }
  }

  private getFallbackTitleText(status: HttpStatus): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return 'Yêu Cầu Không Hợp Lệ'
      case HttpStatus.UNAUTHORIZED:
        return 'Không Được Phép'
      case HttpStatus.FORBIDDEN:
        return 'Bị Cấm'
      case HttpStatus.NOT_FOUND:
        return 'Không Tìm Thấy'
      case HttpStatus.CONFLICT:
        return 'Xung Đột'
      case HttpStatus.UNPROCESSABLE_ENTITY:
        return 'Không Thể Xử Lý Đối Tượng'
      case HttpStatus.PRECONDITION_FAILED:
        return 'Điều Kiện Tiên Quyết Thất Bại'
      case HttpStatus.INTERNAL_SERVER_ERROR:
        return 'Lỗi Máy Chủ Nội Bộ'
      case HttpStatus.SERVICE_UNAVAILABLE:
        return 'Dịch Vụ Không Khả Dụng'
      default: {
        const statusText = Object.keys(HttpStatus).find((key) => HttpStatus[key] === status)
        return statusText
          ? statusText
              .split('_')
              .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
              .join(' ')
          : 'Lỗi HTTP'
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
