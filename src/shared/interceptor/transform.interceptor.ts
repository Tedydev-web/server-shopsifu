import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common'
import { Observable } from 'rxjs'
import { switchMap } from 'rxjs/operators'
import { I18nService } from 'nestjs-i18n'
import { Request, Response } from 'express'

export interface StandardResponse {
  success: true
  statusCode: number
  message: string
  data?: any
  metadata?: Record<string, any>
  timestamp: string
  path: string
  requestId?: string
}

@Injectable()
export class TransformInterceptor implements NestInterceptor {
  constructor(private readonly i18n: I18nService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<StandardResponse> {
    const request = context.switchToHttp().getRequest<Request>()
    const response = context.switchToHttp().getResponse<Response>()
    const statusCode = response.statusCode

    return next.handle().pipe(
      switchMap(async (responseData) => {
        // Handle empty responses or direct primitive values
        if (responseData === null || responseData === undefined) {
          return this.createStandardResponse(statusCode, 'global.success.GENERAL', null, request, null)
        }

        // Handle string responses (for backwards compatibility)
        if (typeof responseData === 'string') {
          return this.createStandardResponse(statusCode, responseData, null, request, null)
        }

        // Handle object responses
        if (typeof responseData === 'object') {
          // If response already contains message property
          if (responseData.message) {
            const translatedMessage = await this.i18n.translate(responseData.message, {
              lang: request.acceptsLanguages(['vi', 'en']) || 'vi',
            })

            return this.createStandardResponse(
              statusCode,
              translatedMessage as string,
              responseData.data || null,
              request,
              responseData.metadata || null,
            )
          }

          // If response has data but no message
          if (responseData.data !== undefined) {
            return this.createStandardResponse(
              statusCode,
              'global.success.GENERAL',
              responseData.data,
              request,
              responseData.metadata || null,
            )
          }

          // Default case: treat entire response as data
          return this.createStandardResponse(statusCode, 'global.success.GENERAL', responseData, request, null)
        }

        // Fallback for other types
        return this.createStandardResponse(statusCode, 'global.success.GENERAL', responseData, request, null)
      }),
    )
  }

  private async createStandardResponse(
    statusCode: number,
    message: string,
    data: any,
    request: Request,
    metadata: Record<string, any> | null,
  ): Promise<StandardResponse> {
    // Translate message if it's a key
    const translatedMessage = message.includes('.')
      ? await this.i18n.translate(message, {
          lang: request.acceptsLanguages(['vi', 'en']) || 'vi',
        })
      : message

    const response: StandardResponse = {
      success: true,
      statusCode,
      message: translatedMessage as string,
      timestamp: new Date().toISOString(),
      path: request.url,
      requestId: request.headers['x-request-id'] as string,
    }

    // Only include data if it's not null/undefined
    if (data !== null && data !== undefined) {
      response.data = data
    }

    // Only include metadata if provided
    if (metadata && Object.keys(metadata).length > 0) {
      response.metadata = metadata
    }

    return response
  }
}
