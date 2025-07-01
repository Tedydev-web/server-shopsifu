import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'

export interface Response<T> {
  data: T
}

@Injectable()
export class TransformInterceptor<T> implements NestInterceptor<T, any> {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data) => {
        // Nếu đã là object có data + metadata (pagination) hoặc có message, không wrap lại
        if (data && typeof data === 'object' && (data.metadata !== undefined || data.message !== undefined)) {
          return data
        }
        // Nếu là primitive hoặc object không chuẩn, wrap vào { data }
        return { data }
      }),
    )
  }
}
