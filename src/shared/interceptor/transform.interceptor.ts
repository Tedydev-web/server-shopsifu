import {
	Injectable,
	NestInterceptor,
	ExecutionContext,
	CallHandler
} from '@nestjs/common'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'

export interface Response<T> {
	data: T
}

@Injectable()
export class TransformInterceptor<T> implements NestInterceptor<T, any> {
	intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
		return next.handle().pipe(
			map(data => {
				// Nếu đã có data và message thì không wrap lại nữa (response có cấu trúc đầy đủ)
				if (
					data &&
					typeof data === 'object' &&
					data.data !== undefined &&
					data.message !== undefined
				) {
					return data
				}

				// Nếu chỉ có message (như change password response)
				if (
					data &&
					typeof data === 'object' &&
					data.message !== undefined &&
					data.data === undefined
				) {
					return data
				}

				// Nếu đã có data, metadata nhưng không có message thì wrap với message mặc định
				if (
					data &&
					typeof data === 'object' &&
					(data.data !== undefined || data.metadata !== undefined)
				) {
					return data
				} else {
					// Wrap data thông thường
					return { data }
				}
			})
		)
	}
}
