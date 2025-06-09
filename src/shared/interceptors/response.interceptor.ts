import { Injectable, NestInterceptor, ExecutionContext, CallHandler, HttpStatus } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { RESPONSE_MESSAGE_KEY } from '../decorators/response-message.decorator'
import { v4 as uuidv4 } from 'uuid'

export interface SuccessResponse<T> {
  status: number
  title: string
  message: string
  data: T | null
  timestamp: string
  requestId: string
}

@Injectable()
export class ResponseInterceptor<T> implements NestInterceptor<T, SuccessResponse<T>> {
  constructor(
    private readonly reflector: Reflector,
    private readonly i18n: I18nService
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<SuccessResponse<T>> {
    const i18nContext = I18nContext.current()
    const request = context.switchToHttp().getRequest()
    const response = context.switchToHttp().getResponse()

    // Lấy message key từ decorator, nếu không có thì dùng key mặc định
    const customMessageKey = this.reflector.get<string>(RESPONSE_MESSAGE_KEY, context.getHandler())
    const messageKey = customMessageKey || 'success.general.defaultMessage'
    // Lấy title key mặc định, có thể mở rộng để cho phép decorator cho title sau
    const titleKey = 'success.general.defaultTitle'

    return next.handle().pipe(
      map((data) => {
        const statusCode = response.statusCode || HttpStatus.OK

        const title = this.i18n.t(titleKey, {
          lang: i18nContext?.lang,
          defaultValue: 'Thao tác thành công' // Fallback cứng nếu key không tồn tại
        })

        const messageFromI18n = this.i18n.t(messageKey, {
          lang: i18nContext?.lang,
          args: typeof data === 'object' && data !== null ? data : {},
          defaultValue: 'Yêu cầu đã được xử lý thành công.' // Fallback cứng nếu key không tồn tại
        })

        // Nếu data là một object và có thuộc tính message, và không có customMessageKey được cung cấp (tức là đang dùng messageKey mặc định)
        // thì ưu tiên sử dụng data.message làm message chính (ví dụ: message đã được dịch từ service)
        let finalMessage = messageFromI18n
        if (
          !customMessageKey &&
          typeof data === 'object' &&
          data !== null &&
          'message' in data &&
          typeof data.message === 'string'
        ) {
          finalMessage = data.message
        }

        // Xóa message khỏi data nếu nó đã được dùng làm message chính
        let responseData = data
        if (typeof data === 'object' && data !== null && 'message' in data && finalMessage === data.message) {
          const { message: _, ...rest } = data
          responseData = Object.keys(rest).length > 0 ? rest : null
        } else if (data === undefined) {
          responseData = null
        }

        return {
          status: statusCode,
          title, // ESLint báo 'as string' là không cần thiết, TypeScript tự suy luận được
          message: finalMessage as string, // Giữ lại để đảm bảo message là string
          data: responseData,
          timestamp: new Date().toISOString(),
          requestId: request.id || uuidv4()
        }
      })
    )
  }
}
