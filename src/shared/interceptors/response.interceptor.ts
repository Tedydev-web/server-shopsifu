import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { I18nService, I18nContext, Path } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'

export interface SuccessResponse<T> {
  status: number
  message: string
  data?: T
  verificationType?: 'OTP' | '2FA'
  [key: string]: any // Allow other fields to pass through
}

@Injectable()
export class ResponseInterceptor<T> implements NestInterceptor<T, SuccessResponse<T>> {
  constructor(
    private readonly reflector: Reflector,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<SuccessResponse<T>> {
    const httpContext = context.switchToHttp()
    const response = httpContext.getResponse()
    const i18nContext = I18nContext.current()

    return next.handle().pipe(
      map((data) => {
        const statusCode = response.statusCode
        const customMessage = data?.message

        const messageKey = (customMessage || 'global.general.success.default') as Path<I18nTranslations>

        // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion
        const message = this.i18n.t(messageKey, { lang: i18nContext?.lang, args: data?.args }) as string

        const finalResponse: Partial<SuccessResponse<T>> = {
          status: statusCode,
          message: message
        }

        // Preserve important fields like verificationType, status (string), etc.
        if (data && typeof data === 'object') {
          // Copy all fields except message (already translated) and data (handled separately)
          Object.keys(data).forEach((key) => {
            if (key !== 'message' && key !== 'data') {
              finalResponse[key] = data[key]
            }
          })

          // Handle data field separately
          if ('data' in data) {
            finalResponse.data = data.data
          } else if (!data.message) {
            // If no explicit data field and no message, treat entire object as data
            finalResponse.data = data
          }
        } else if (data && !data?.message) {
          finalResponse.data = data
        }

        return finalResponse as SuccessResponse<T>
      })
    )
  }
}
