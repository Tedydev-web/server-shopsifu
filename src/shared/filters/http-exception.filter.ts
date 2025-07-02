import { ArgumentsHost, Catch, HttpException, Logger } from '@nestjs/common'
import { BaseExceptionFilter } from '@nestjs/core'
import { I18nService } from 'nestjs-i18n'
import { ZodSerializationException } from 'nestjs-zod'
import { I18nTranslations } from 'src/generated/i18n.generated'

@Catch(HttpException)
export class HttpExceptionFilter extends BaseExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name)
  constructor(private readonly i18n: I18nService<I18nTranslations>) {
    super()
  }

  catch(exception: HttpException, host: ArgumentsHost) {
    if (exception instanceof ZodSerializationException) {
      const zodError = exception.getZodError()
      this.logger.error(`ZodSerializationException: ${zodError.message}`)
      super.catch(exception, host)
      return
    }

    const response = exception.getResponse() as any
    // Lấy ngôn ngữ từ header, nếu không có thì dùng default
    const lang = host.switchToHttp().getRequest().i18nLang

    // Nếu response.message là một mảng (trường hợp custom exception)
    if (Array.isArray(response.message)) {
      // Dịch từng message trong mảng
      response.message = response.message.map((item: any) => {
        if (item.message && typeof item.message === 'string') {
          return {
            ...item,
            message: this.i18n.t(item.message, { lang }),
          }
        }
        return item
      })
    }
    // Nếu response.message là một string
    else if (typeof response.message === 'string') {
      response.message = this.i18n.t(response.message, { lang })
    }

    // Tạo một exception mới với message đã được dịch
    const translatedException = new HttpException(response, exception.getStatus())

    super.catch(translatedException, host)
  }
}
