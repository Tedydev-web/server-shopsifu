import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { Reflector } from '@nestjs/core'
import { SKIP_TRANSFORM_KEY } from 'src/shared/decorators/auth.decorator'

@Injectable()
export class TransformInterceptor implements NestInterceptor {
  constructor(private reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // Kiểm tra xem có skip transform không
    const skipTransform = this.reflector.get<boolean>(SKIP_TRANSFORM_KEY, context.getHandler())
    if (skipTransform) {
      return next.handle()
    }

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

        // Kiểm tra nếu response có cấu trúc { data, metadata } thì giữ nguyên
        if (typeof data === 'object' && data !== null && 'data' in data && 'metadata' in data) {
          return { statusCode, message, timestamp, ...data }
        }

        // Xử lý trường hợp chỉ có data
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
