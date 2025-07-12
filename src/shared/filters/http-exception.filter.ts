import { Logger, Catch, ArgumentsHost, HttpException } from '@nestjs/common'
import { BaseExceptionFilter } from '@nestjs/core'
import { ZodSerializationException } from 'nestjs-zod'
import { I18nContext } from 'nestjs-i18n'
import { Response } from 'express'

@Catch(HttpException)
export class HttpExceptionFilter extends BaseExceptionFilter {
	private readonly logger = new Logger(HttpExceptionFilter.name)

	catch(exception: HttpException, host: ArgumentsHost) {
		const ctx = host.switchToHttp()
		const response = ctx.getResponse<Response>()
		const request = ctx.getRequest()

		if (exception instanceof ZodSerializationException) {
			const zodError = exception.getZodError()
			this.logger.error(`ZodSerializationException: ${zodError.message}`)
		}

		const status = exception.getStatus()
		const exceptionResponse = exception.getResponse() as any

		// Xử lý i18n translation cho error messages
		const translatedResponse = this.translateErrorResponse(
			exceptionResponse,
			request
		)

		// Log error với context
		this.logger.error(
			`HTTP Exception: ${status} - ${JSON.stringify(translatedResponse)}`,
			exception.stack
		)

		// Trả về response đã được translate
		response.status(status).json(translatedResponse)
	}

	private translateErrorResponse(exceptionResponse: any, request: any): any {
		const i18n = I18nContext.current()
		const lang = request.lang || i18n?.lang || 'vi'

		// Nếu response đã là string, tìm translation key
		if (typeof exceptionResponse === 'string') {
			const translatedMessage =
				i18n?.t(exceptionResponse) || exceptionResponse
			return {
				statusCode: 500,
				message: translatedMessage,
				error: 'Internal Server Error'
			}
		}

		// Nếu response là object với message array (validation errors)
		if (Array.isArray(exceptionResponse.message)) {
			const translatedMessages = exceptionResponse.message.map(
				(error: any) => {
					if (error.message && typeof error.message === 'string') {
						const translatedMessage =
							i18n?.t(error.message) || error.message
						return {
							...error,
							message: translatedMessage
						}
					}
					return error
				}
			)

			return {
				...exceptionResponse,
				message: translatedMessages
			}
		}

		// Nếu response là object với message string
		if (
			exceptionResponse.message &&
			typeof exceptionResponse.message === 'string'
		) {
			const translatedMessage =
				i18n?.t(exceptionResponse.message) || exceptionResponse.message
			return {
				...exceptionResponse,
				message: translatedMessage
			}
		}

		// Nếu không có message, thử translate error field
		if (
			exceptionResponse.error &&
			typeof exceptionResponse.error === 'string'
		) {
			const translatedError =
				i18n?.t(exceptionResponse.error) || exceptionResponse.error
			return {
				...exceptionResponse,
				error: translatedError
			}
		}

		return exceptionResponse
	}
}
