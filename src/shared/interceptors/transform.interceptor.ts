import { CallHandler, ExecutionContext, Inject, Injectable, NestInterceptor, Logger } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { Request, Response } from 'express'

// Định nghĩa type cho hàm translate
type TranslateFunction = (key: string, options?: Record<string, any>) => string

export interface SuccessResponse<T> {
  success: boolean
  statusCode: number
  message: string
  data: T | null
  metadata?: Record<string, any>
}

@Injectable()
export class TransformInterceptor<T> implements NestInterceptor<T, SuccessResponse<T>> {
  private readonly logger = new Logger(TransformInterceptor.name)

  constructor(
    @Inject(I18nService) private readonly i18n: I18nService,
    private readonly reflector: Reflector
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<SuccessResponse<T>> {
    const httpContext = context.switchToHttp()
    const response = httpContext.getResponse<Response>()
    const request = httpContext.getRequest<Request>()
    const statusCode = response.statusCode

    // Định nghĩa hàm t với type rõ ràng
    const t: TranslateFunction = (key, options) =>
      this.i18n.t(key, { lang: options?.lang ?? I18nContext.current()?.lang ?? 'vi' })

    return next.handle().pipe(
      map((result: any) => {
        this.logger.debug(`Transforming response for request: ${request.method} ${request.url}`)

        // Case 1: Controller trả về object đầy đủ với message và data
        if (result && typeof result.message === 'string' && result.data !== undefined) {
          const message = t(result.message)
          return {
            success: true,
            statusCode,
            message,
            data: result.data,
            metadata: result.meta
          }
        }

        // Case 2: Lấy message từ decorator @SuccessMessage hoặc fallback
        const i18nMessageKey = 'global.success.general.default'
        const message = t(i18nMessageKey)

        // Case 3: Xử lý response phân trang (paginated)
        if (result && result.meta && result.data) {
          return {
            success: true,
            statusCode,
            message,
            data: result.data,
            metadata: result.meta
          }
        }

        // Case 4: Response thông thường
        return {
          success: true,
          statusCode,
          message,
          data: result === undefined ? null : result
        }
      })
    )
  }
}
