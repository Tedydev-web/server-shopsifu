import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { I18nService, I18nContext, Path } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { v4 as uuidv4 } from 'uuid'

export interface SuccessResponse<T> {
  status: number
  title: string
  message: string
  data: T | null
  timestamp: string
  requestId: string
}

@Injectable()
export class ResponseInterceptor<T> implements NestInterceptor<T, SuccessResponse<T>> {
  constructor(
    private readonly reflector: Reflector,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<SuccessResponse<T>> {
    const httpContext = context.switchToHttp()
    const request = httpContext.getRequest()
    const response = httpContext.getResponse()
    const i18nContext = I18nContext.current()

    return next.handle().pipe(
      map((data) => {
        const statusCode = response.statusCode
        const customMessage = data?.message
        const customTitle = data?.title

        const titleKey = (customTitle || 'global.general.success.default') as Path<I18nTranslations>
        const messageKey = (customMessage || 'global.general.success.default') as Path<I18nTranslations>

        // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion
        const title = this.i18n.t(titleKey, { lang: i18nContext?.lang, args: data?.args }) as string
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion
        const message = this.i18n.t(messageKey, { lang: i18nContext?.lang, args: data?.args }) as string

        // Prevent meta-wrapping of already wrapped data
        const finalData = data?.data ?? (data?.message ? null : data)

        return {
          status: statusCode,
          title: title,
          message: message,
          data: finalData,
          timestamp: new Date().toISOString(),
          requestId: request.id || uuidv4()
        }
      })
    )
  }
}
