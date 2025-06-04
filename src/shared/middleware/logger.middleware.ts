import { Injectable, NestMiddleware, Logger } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import { REQUEST_USER_KEY } from '../constants/auth.constants'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  private logger = new Logger('HTTP')

  use(req: Request, res: Response, next: NextFunction) {
    const { method, originalUrl, ip } = req
    const userAgent = req.get('user-agent') || ''

    const startTime = Date.now()

    res.on('finish', () => {
      const { statusCode } = res
      const responseTime = Date.now() - startTime
      const contentLength = res.get('content-length')
      const user = req[REQUEST_USER_KEY] as AccessTokenPayload | undefined
      const userId = user?.userId || 'anonymous'

      this.logger.log(
        `${method} ${originalUrl} ${statusCode} ${responseTime}ms ${contentLength || '-'} - ${userAgent} ${ip} - User: ${userId}`
      )

      // Log slow requests
      if (responseTime > 1000) {
        this.logger.warn(`Slow request: ${method} ${originalUrl} - ${responseTime}ms`)
      }

      // Log errors
      if (statusCode >= 400) {
        const level = statusCode >= 500 ? 'error' : 'warn'
        this.logger[level](`Request error: ${method} ${originalUrl} ${statusCode}`)
      }
    })

    next()
  }
}
