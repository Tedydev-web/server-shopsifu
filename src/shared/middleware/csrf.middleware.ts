import { Injectable, NestMiddleware, Logger } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import csurf from 'csurf'
import envConfig from '../config'
import { SecurityHeaders } from '../constants/auth.constant'

@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  private readonly logger = new Logger(CsrfMiddleware.name)
  private readonly csrfProtection: any

  constructor() {
    const csrfSecretCookieConfig = envConfig.cookie.csrfSecret
    this.csrfProtection = csurf({
      cookie: {
        key: csrfSecretCookieConfig.name,
        httpOnly: csrfSecretCookieConfig.httpOnly,
        secure: csrfSecretCookieConfig.secure,
        sameSite: csrfSecretCookieConfig.sameSite,
        signed: csrfSecretCookieConfig.signed,
        path: csrfSecretCookieConfig.path,
        domain: csrfSecretCookieConfig.domain
      },
      ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
      value: (req: Request) => this.csrfTokenExtractor(req)
    })
  }

  use(req: Request, res: Response, next: NextFunction) {
    if (
      req.path.startsWith('/api/v1/auth/google/callback') ||
      req.path.startsWith('/api/v1/webhook') ||
      req.path.startsWith('/api/v1/health')
    ) {
      return next()
    }

    this.csrfProtection(req, res, (err: any) => {
      if (err) {
        res.status(403).json({
          statusCode: 403,
          message: 'Invalid CSRF token',
          error: 'Forbidden'
        })
        return
      }

      const csrfTokenVal = req.csrfToken?.()
      if (csrfTokenVal) {
        const csrfTokenCookieConfig = envConfig.cookie.csrfToken
        res.setHeader(SecurityHeaders.XSRF_TOKEN_HEADER, csrfTokenVal)
        res.cookie(csrfTokenCookieConfig.name, csrfTokenVal, {
          httpOnly: csrfTokenCookieConfig.httpOnly,
          sameSite: csrfTokenCookieConfig.sameSite,
          secure: csrfTokenCookieConfig.secure,
          path: csrfTokenCookieConfig.path,
          domain: csrfTokenCookieConfig.domain
        })
      }

      next()
    })
  }

  private csrfTokenExtractor(req: Request): string {
    const xsrfHeader = SecurityHeaders.XSRF_TOKEN_HEADER.toLowerCase()
    const csrfHeader = 'x-csrf-token'

    // Kiểm tra cả hai header
    const tokenFromXsrfHeader = req.headers[xsrfHeader]
    const tokenFromCsrfHeader = req.headers[csrfHeader]
    const tokenFromBodyOrQuery = req.body?._csrf || req.query?._csrf

    let token = tokenFromXsrfHeader || tokenFromCsrfHeader || tokenFromBodyOrQuery

    if (Array.isArray(token)) {
      token = token[0]
    }

    if (token && typeof token === 'string') {
      this.logger.debug(`CSRF token được trích xuất từ request: ${token.substring(0, 6)}...`)
    }

    return (token as string) || ''
  }
}
