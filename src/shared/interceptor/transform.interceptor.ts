import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'

@Injectable()
export class TransformInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data) => {
        const ctx = context.switchToHttp()
        const response = ctx.getResponse()
        const statusCode = response.statusCode
        const message = data?.message || 'Thành công'
        const timestamp = new Date().toISOString()
        if (data?.message) {
          const { message, ...rest } = data
          data = rest
        }
        if (typeof data === 'object' && data !== null && 'data' in data) {
          data = data.data
        }
        const isEmptyObject =
          typeof data === 'object' && data !== null && Object.keys(data).length === 0 && data.constructor === Object
        if (data === undefined || data === null || isEmptyObject) {
          return { statusCode, message, timestamp }
        }
        return { statusCode, message, timestamp, data }
      })
    )
  }
}
