import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'

export interface StandardSuccessResponse<T> {
  statusCode: number
  message: string // i18n key
  data?: T // data có thể là optional, ví dụ khi logout, delete
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
        const statusCode = response.statusCode // Lấy statusCode từ response đã được set bởi NestJS

        let messageKey = 'Global.Success' // Default success message key
        let dataPayload: T | undefined = undefined

        if (responseData && typeof responseData === 'object') {
          if ('message' in responseData && typeof responseData.message === 'string') {
            messageKey = responseData.message
            // If 'data' also exists, use it; otherwise, dataPayload remains undefined (e.g., for simple message responses)
            if ('data' in responseData) {
              dataPayload = responseData.data as T
            } else {
              // This handles cases where the service returns { message: 'Some.Key' } without a 'data' field.
              // The original responseData itself isn't the payload if it was a message object.
              dataPayload = undefined
            }
          } else {
            // If it's an object but not a { message, data? } structure, assume the whole object is the data.
            dataPayload = responseData as T
          }
        } else if (responseData !== undefined && responseData !== null) {
          // For primitive types or other non-object, non-null/undefined responses
          dataPayload = responseData as T
        }
        // If responseData was undefined or null, dataPayload remains undefined, messageKey is Global.Success

        return {
          statusCode,
          message: messageKey,
          data: dataPayload
        }
      })
    )
  }
}
