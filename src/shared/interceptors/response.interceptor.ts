import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { I18nService, I18nContext, Path } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'

export interface SuccessResponse<T> {
  status: number
  message: string
  data: T | null
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

        const messageKey = (customMessage || 'global.general.success.default') as Path<I18nTranslations>

        // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion
        const message = this.i18n.t(messageKey, { lang: i18nContext?.lang, args: data?.args }) as string

        const finalResponse: Partial<SuccessResponse<T>> = {
          status: statusCode,
          message: message
        }

        if (data && typeof data === 'object' && 'data' in data) {
          finalResponse.data = data.data
        } else if (data && !data.message) {
          finalResponse.data = data
        }

        return finalResponse as SuccessResponse<T>
      })
    )
  }
}
