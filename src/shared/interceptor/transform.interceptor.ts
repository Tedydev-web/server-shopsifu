import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'

export interface StandardSuccessResponse<T> {
  statusCode: number
  message: string
  data?: T
}

@Injectable()
export class TransformInterceptor<T = any>
  implements NestInterceptor<T | { message: string; data?: T }, StandardSuccessResponse<T>>
{
  intercept(context: ExecutionContext, next: CallHandler): Observable<StandardSuccessResponse<T>> {
    return next.handle().pipe(
      map((responseData) => {
        const ctx = context.switchToHttp()
        const response = ctx.getResponse()
        const statusCode = response.statusCode

        let messageKey = 'Global.Success'
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
