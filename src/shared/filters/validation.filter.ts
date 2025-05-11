import { ExceptionFilter, Catch, ArgumentsHost, HttpStatus } from '@nestjs/common'
import { ZodError } from 'zod'
import { Request, Response } from 'express'
import { createErrorResponse } from '../models/error-response.model'
import { RequestErrorKeys } from '../../routes/auth/error.keys'

@Catch(ZodError)
export class ZodValidationFilter implements ExceptionFilter {
  catch(exception: ZodError, host: ArgumentsHost) {
    const ctx = host.switchToHttp()
    const response = ctx.getResponse<Response>()
    const request = ctx.getRequest<Request>()

    const formattedErrors = exception.errors.map((error) => {
      // Chuyển đổi thông báo lỗi thành errorCode cho đa ngôn ngữ
      // Format: error.[field].[type]
      const path = error.path.join('.')
      const errorType = error.code.toLowerCase()
      const errorCode = `error.${path || 'general'}.${errorType}`

      return {
        message: error.message, // Giữ lại cho debugging
        path: path,
        errorCode: errorCode // Thêm errorCode cho frontend dịch
      }
    })

    response
      .status(HttpStatus.UNPROCESSABLE_ENTITY)
      .json(
        createErrorResponse(
          RequestErrorKeys.VALIDATION_FAILED,
          HttpStatus.UNPROCESSABLE_ENTITY,
          'Validation Error',
          formattedErrors
        )
      )
  }
}
