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
        const message = response.locals?.message || 'Thành công'
        const timestamp = new Date().toISOString()
        // Chỉ spread ra ngoài nếu có cả 'data' và 'metadata' (trường hợp pagination)
        if (typeof data === 'object' && data !== null && 'data' in data && 'metadata' in data) {
          return { statusCode, message, timestamp, ...data }
        }
        // Còn lại tất cả đều bọc vào data (object, array, primitive)
        return { statusCode, message, timestamp, data }
      })
    )
  }
}
