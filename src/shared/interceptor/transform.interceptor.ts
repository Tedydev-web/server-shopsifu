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
        // Nếu là array thì trả về items, nếu là object thì spread ra ngoài, nếu là primitive thì bọc trong data
        if (Array.isArray(data)) {
          return { statusCode, message, timestamp, items: data }
        }
        if (typeof data === 'object' && data !== null) {
          return { statusCode, message, timestamp, ...data }
        }
        return { statusCode, message, timestamp, data }
      })
    )
  }
}
