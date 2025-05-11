import { ExceptionFilter, Catch, ArgumentsHost, HttpStatus } from '@nestjs/common'
import { ZodError } from 'zod'
import { Request, Response } from 'express'

@Catch(ZodError)
export class ZodValidationFilter implements ExceptionFilter {
  catch(exception: ZodError, host: ArgumentsHost) {
    const ctx = host.switchToHttp()
    const response = ctx.getResponse<Response>()
    const request = ctx.getRequest<Request>()

    const formattedErrors = exception.errors.map((error) => ({
      message: error.message,
      path: error.path.join('.'),
      code: error.code
    }))

    response.status(HttpStatus.UNPROCESSABLE_ENTITY).json({
      statusCode: HttpStatus.UNPROCESSABLE_ENTITY,
      timestamp: new Date().toISOString(),
      path: request.url,
      errors: formattedErrors
    })
  }
}
