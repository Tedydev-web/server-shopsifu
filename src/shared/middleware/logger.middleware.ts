import { Injectable, NestMiddleware, Logger } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import { AccessTokenPayload } from '../types/jwt.type'
import { REQUEST_USER_KEY } from '../constants/auth.constant'

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  private readonly builtInLogger = new Logger('HTTP')

  use(request: Request, response: Response, next: NextFunction): void {
    const { ip, method, originalUrl, headers: originalHeaders } = request
    const userAgent = originalHeaders['user-agent'] || ''
    const startTime = Date.now()

    response.on('finish', () => {
      const { statusCode } = response
      const contentLength = response.get('content-length')
      const elapsedTime = Date.now() - startTime

      const message = `${method} ${originalUrl} ${statusCode} ${contentLength || '-'} - ${elapsedTime}ms - ${userAgent} ${ip}`

      if (statusCode >= 500) {
        this.builtInLogger.error(message)
      } else if (statusCode >= 400) {
        this.builtInLogger.warn(message)
      } else {
        this.builtInLogger.log(message)
      }

      void (() => {
        const activeUser = request[REQUEST_USER_KEY] as AccessTokenPayload | undefined
        let userId: number | undefined
        let userEmail: string | undefined

        if (activeUser) {
          userId = activeUser.userId
        }

        const allowedHeaderKeys = [
          'user-agent',
          'referer',
          'content-type',
          'x-forwarded-for',
          'accept-language',
          'x-request-id'
        ]
        const sensitiveHeaderKeysPattern = [
          /^authorization$/i,
          /^cookie$/i,
          /^x-api-key$/i,
          /^x-csrf-token$/i,
          /secret/i,
          /token/i,
          /password/i
        ]

        const filteredHeaders: Record<string, string | string[] | undefined> = {}
        for (const key in originalHeaders) {
          const lowerKey = key.toLowerCase()
          let isSensitive = false
          for (const pattern of sensitiveHeaderKeysPattern) {
            if (typeof pattern === 'string' && lowerKey === pattern) {
              isSensitive = true
              break
            }
            if (pattern instanceof RegExp && pattern.test(lowerKey)) {
              isSensitive = true
              break
            }
          }

          if (isSensitive) {
            filteredHeaders[key] = '[REDACTED_SENSITIVE_HEADER]'
          } else if (allowedHeaderKeys.includes(lowerKey)) {
            filteredHeaders[key] = originalHeaders[key]
          }
        }
      })()
    })

    next()
  }
}
