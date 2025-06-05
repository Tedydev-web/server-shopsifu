import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { I18nTranslations, I18nPath } from '../../generated/i18n.generated'
import { I18nService } from 'nestjs-i18n'

export interface StandardSuccessResponse<T> {
  statusCode: number
  message: string
  data?: T
}

@Injectable()
export class TransformInterceptor<T = any>
  implements NestInterceptor<T | { message: string; data?: T }, StandardSuccessResponse<T>>
{
  constructor(private readonly i18nService: I18nService<I18nTranslations>) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<StandardSuccessResponse<T>> {
    return next.handle().pipe(
      map((responseData) => {
        const ctx = context.switchToHttp()
        const response = ctx.getResponse()
        const statusCode = response.statusCode

        let messageKey = this.i18nService.t('global.success.general.default')
        let dataPayload: T | undefined = undefined

        if (responseData && typeof responseData === 'object') {
          if ('message' in responseData && typeof responseData.message === 'string') {
            messageKey = responseData.message

            if ('data' in responseData) {
              dataPayload = responseData.data as T
            } else {
              dataPayload = undefined
            }
          } else {
            dataPayload = responseData as T
          }
        } else if (responseData !== undefined && responseData !== null) {
          dataPayload = responseData as T
        }

        return {
          statusCode,
          message: messageKey,
          data: dataPayload
        }
      })
    )
  }
}
