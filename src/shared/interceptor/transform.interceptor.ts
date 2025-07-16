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
        if (
          typeof data === 'object' &&
          data !== null &&
          'data' in data &&
          ('totalItems' in data || 'metadata' in data)
        ) {
          return { statusCode, message, timestamp, ...data }
        }
        return { statusCode, message, timestamp, data }
      })
    )
  }
}
