import { CallHandler, ExecutionContext, Inject, Injectable, NestInterceptor, Logger } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'
import { isObject } from '../utils/type-guards.utils'
import { Request, Response } from 'express'
import { SUCCESS_MESSAGE_KEY } from 'src/shared/decorators/success-message.decorator'

/**
 * Interface cho một response thành công chuẩn hóa.
 */
export interface SuccessResponse<T> {
  success: boolean
  statusCode: number
  message: string
  data: T | null
  metadata?: Record<string, any>
}

/**
 * Interceptor này bắt tất cả các response thành công và định dạng chúng
 * theo một cấu trúc `SuccessResponse` nhất quán.
 */
@Injectable()
export class TransformInterceptor<T> implements NestInterceptor<T, SuccessResponse<T>> {
  private readonly logger = new Logger(TransformInterceptor.name)

  constructor(
    @Inject(I18nService) private readonly i18n: I18nService<I18nTranslations>,
    private readonly reflector: Reflector
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<SuccessResponse<T>> {
    const httpContext = context.switchToHttp()
    const response = httpContext.getResponse<Response>()
    const request = httpContext.getRequest<Request>()
    const statusCode = response.statusCode

    return next.handle().pipe(
      map((result: any) => {
        // Case 1: The service/controller returns a full response object. This is preferred for complex cases.
        if (result && result.message && result.data !== undefined) {
          const message = this.i18n.t(result.message as I18nPath, { lang: I18nContext.current()?.lang }) as string
          return {
            success: true,
            statusCode,
            message,
            data: result.data,
            metadata: result.meta
          }
        }

        // Case 2: The controller returns data, and the message is provided by the @SuccessMessage decorator.
        const i18nMessageKey =
          this.reflector.get<I18nPath>(SUCCESS_MESSAGE_KEY, context.getHandler()) || 'global.success.general.default'

        const message = this.i18n.t(i18nMessageKey, {
          lang: I18nContext.current()?.lang
        }) as string

        // Handle paginated responses
        if (result && result.meta && result.data) {
          return {
            success: true,
            statusCode,
            message,
            data: result.data,
            metadata: result.meta
          }
        }

        // Handle regular data responses
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
