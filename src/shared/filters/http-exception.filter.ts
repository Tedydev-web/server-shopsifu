import { Logger, Catch, ArgumentsHost, HttpException, HttpStatus } from '@nestjs/common'
import { BaseExceptionFilter } from '@nestjs/core'
import { ZodSerializationException } from 'nestjs-zod'
import { v4 as uuidv4 } from 'uuid'
import { Request, Response } from 'express'

interface ErrorItem {
  code: string
  path?: string
  params?: Record<string, any>
}

@Catch(HttpException)
export class HttpExceptionFilter extends BaseExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name)

  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp()
    const response = ctx.getResponse<Response>()
    const request = ctx.getRequest<Request>()
    const status = exception.getStatus()
    const errorResponse = exception.getResponse()
    const timestamp = new Date().toISOString()
    const requestId = uuidv4()

    const errorMessage: any = errorResponse
    let errors: ErrorItem[] = []

    // Xử lý lỗi từ ZodSerializationException
    if (exception instanceof ZodSerializationException) {
      const zodError = exception.getZodError()
      this.logger.error(`ZodSerializationException: ${zodError.message}`)

      errors = zodError.errors.map((err) => ({
        code: `ERROR.VALIDATION_FAILED`,
        path: err.path.join('.'),
        params: {
          message: err.message
        }
      }))
    }
    // Xử lý lỗi từ HttpException thông thường
    else if (typeof errorResponse === 'object') {
      if (Array.isArray(errorResponse['message'])) {
        errors = errorResponse['message'].map((item) => {
          // Log để debug
          this.logger.debug(`Processing error item: ${JSON.stringify(item)}`)

          // Xử lý trường hợp message đã là code lỗi chuẩn
          let errorCode = 'ERROR.UNKNOWN'
          if (item.message) {
            errorCode = item.message.startsWith('ERROR.')
              ? item.message
              : `ERROR.${item.message.toUpperCase().replace(/\s+/g, '_')}`
          }

          return {
            code: errorCode,
            path: item.path,
            params: item.params || {}
          }
        })
      } else if (errorResponse['message']) {
        const message = errorResponse['message']
        let errorCode = 'ERROR.UNKNOWN'
        if (typeof message === 'string') {
          errorCode = message.startsWith('ERROR.') ? message : `ERROR.${message.toUpperCase().replace(/\s+/g, '_')}`
        }

        errors = [
          {
            code: errorCode,
            params: typeof message !== 'string' ? { details: message } : {}
          }
        ]
      }
    } else if (typeof errorResponse === 'string') {
      let errorCode = 'ERROR.UNKNOWN'
      if (errorResponse) {
        errorCode = errorResponse.startsWith('ERROR.')
          ? errorResponse
          : `ERROR.${errorResponse.toUpperCase().replace(/\s+/g, '_')}`
      }

      errors = [
        {
          code: errorCode,
          params: {}
        }
      ]
    }

    const formattedError = {
      success: false,
      statusCode: status,
      errors,
      timestamp,
      requestId,
      path: request.url
    }

    response.status(status).json(formattedError)
  }
}
