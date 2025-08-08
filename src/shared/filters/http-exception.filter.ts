import { Logger, Catch, ArgumentsHost, HttpException } from '@nestjs/common'
import { BaseExceptionFilter } from '@nestjs/core'
import { ZodSerializationException } from 'nestjs-zod'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { Response } from 'express'

@Catch(HttpException)
export class HttpExceptionFilter extends BaseExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name)

  constructor(private readonly i18n: I18nService<I18nTranslations>) {
    super()
  }

  async catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp()
    const response = ctx.getResponse<Response>()
    const request = ctx.getRequest()

    if (exception instanceof ZodSerializationException) {
      const zodError = exception.getZodError()
      this.logger.error(`ZodSerializationException: ${zodError.message}`)
    }

    const status = exception.getStatus()
    const exceptionResponse = exception.getResponse() as any

    // Lấy language từ request header hoặc query parameter
    const lang = request.headers['accept-language'] || request.query.lang || 'en'
    const language = Array.isArray(lang) ? lang[0] : lang

    // Kiểm tra nếu message là translation key (có dạng 'global.global.error.XXX')
    if (exceptionResponse.message) {
      try {
        let translatedMessage: any

        // Xử lý trường hợp message là string
        if (typeof exceptionResponse.message === 'string') {
          const messageKey = exceptionResponse.message

          // Kiểm tra xem có phải là translation key không
          if (messageKey.includes('.')) {
            translatedMessage = await this.i18n.translate(messageKey as keyof I18nTranslations, { lang: language })
          } else {
            translatedMessage = messageKey
          }
        }
        // Xử lý trường hợp message là array (validation errors)
        else if (Array.isArray(exceptionResponse.message)) {
          translatedMessage = await Promise.all(
            exceptionResponse.message.map(async (error: any) => ({
              ...error,
              message:
                typeof error.message === 'string' && error.message.includes('.')
                  ? await this.i18n.translate(error.message as keyof I18nTranslations, { lang: language })
                  : error.message
            }))
          )
        }
        // Trường hợp khác, giữ nguyên
        else {
          translatedMessage = exceptionResponse.message
        }

        // Cập nhật response với message đã được translate
        const errorResponse = {
          message: translatedMessage,
          error: exceptionResponse.error || exception.message,
          statusCode: status
        }

        return response.status(status).json(errorResponse)
      } catch (translateError) {
        this.logger.warn(`Failed to translate message: ${JSON.stringify(exceptionResponse.message)}`, translateError)
        // Nếu không translate được, giữ nguyên message gốc
      }
    }

    super.catch(exception, host)
  }
}
