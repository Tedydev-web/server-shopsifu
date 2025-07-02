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
        // Nếu đã có data, metadata hoặc message thì không wrap lại nữa
        if (
          data &&
          typeof data === 'object' &&
          (data.data !== undefined || data.metadata !== undefined || data.message !== undefined)
        ) {
          return data
        } else {
          return { data }
        }
      }),
    )
  }
}
