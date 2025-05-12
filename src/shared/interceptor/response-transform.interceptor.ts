import { Injectable, NestInterceptor, ExecutionContext, CallHandler, HttpStatus } from '@nestjs/common'
import { Observable } from 'rxjs'
import { map } from 'rxjs/operators'
import { v4 as uuidv4 } from 'uuid'

interface ResponseMetadata {
  page?: number
  limit?: number
  total?: number
  totalPages?: number
}

interface MessageFormat {
  code: string
  params?: Record<string, any>
}

interface ErrorFormat {
  code: string
  path?: string
  params?: Record<string, any>
}

export interface ResponseFormat<T> {
  success: boolean
  statusCode: number
  message?: MessageFormat | string
  errors?: ErrorFormat[] | string[]
  data?: T
  meta?: ResponseMetadata
  timestamp: string
  requestId: string
}

@Injectable()
export class ResponseTransformInterceptor<T> implements NestInterceptor<T, ResponseFormat<T>> {
  intercept(context: ExecutionContext, next: CallHandler): Observable<ResponseFormat<T>> {
    const now = new Date()
    const requestId = uuidv4()
    const ctx = context.switchToHttp()
    const response = ctx.getResponse()
    const statusCode = response.statusCode || HttpStatus.OK
    const success = statusCode < 400

    return next.handle().pipe(
      map((resultData) => {
        // Xử lý phản hồi chuẩn
        const formattedResponse: ResponseFormat<T> = {
          success,
          statusCode,
          timestamp: now.toISOString(),
          requestId
        }

        // Trường hợp resultData đã là một object có cấu trúc riêng
        if (resultData) {
          // Xử lý phản hồi có message
          if (resultData.message) {
            // Nếu message là string, chuyển thành object với code
            if (typeof resultData.message === 'string') {
              formattedResponse.message = {
                code: resultData.message
              }
            } else {
              formattedResponse.message = resultData.message
            }
            delete resultData.message
          }

          // Xử lý lỗi
          if (
            resultData.errors ||
            (Array.isArray(resultData) && resultData.some((item) => item.message && item.path))
          ) {
            formattedResponse.errors = Array.isArray(resultData) ? resultData : resultData.errors || []

            // Chuẩn hóa mảng lỗi
            if (Array.isArray(formattedResponse.errors)) {
              formattedResponse.errors = formattedResponse.errors.map((error) => {
                if (typeof error === 'string') {
                  return { code: error }
                }

                if (error.message && !error.code) {
                  return {
                    code: error.message,
                    path: error.path,
                    params: error.params
                  }
                }

                return error
              })
            }

            delete resultData.errors
          }

          // Xử lý metadata phân trang
          if (resultData.meta || resultData.pagination) {
            formattedResponse.meta = resultData.meta || resultData.pagination
            delete resultData.meta
            delete resultData.pagination
          }

          // Gán dữ liệu còn lại vào data
          const remainingData = { ...resultData }
          delete remainingData.statusCode

          // Kiểm tra xem có dữ liệu còn lại không
          if (Object.keys(remainingData).length > 0) {
            formattedResponse.data = remainingData
          }
        }

        return formattedResponse
      })
    )
  }
}
