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
    this.logger.debug(`CSRF Middleware - Incoming request: ${req.method} ${req.path}`)

    if (
      req.path.startsWith('/api/v1/auth/google/callback') ||
      req.path.startsWith('/api/v1/webhook') ||
      req.path.startsWith('/api/v1/health')
    ) {
      this.logger.debug(`CSRF Middleware - Bypassing for specific path: ${req.path}`)
      return next()
    }

    this.csrfProtection(req, res, (err: any) => {
      if (err) {
        this.logger.error(
          `CSRF Protection Error: ${err.code === 'EBADCSRFTOKEN' ? 'Invalid CSRF token' : err.message}`,
          err.stack
        )
        this.logger.error(
          `CSRF Secret Cookie (${envConfig.cookie.csrfSecret.name} value from req.signedCookies): ${req.signedCookies?.[envConfig.cookie.csrfSecret.name]}`
        )
        this.logger.error(
          `CSRF Token Cookie (${envConfig.cookie.csrfToken.name} value from req.cookies): ${req.cookies?.[envConfig.cookie.csrfToken.name]}`
        )
        this.logger.error(
          `Header value (${SecurityHeaders.CSRF_TOKEN_HEADER} from req.headers): ${String(req.headers[SecurityHeaders.CSRF_TOKEN_HEADER.toLowerCase()] || '')}`
        )
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
        res.setHeader(SecurityHeaders.CSRF_TOKEN_HEADER, csrfTokenVal)
        res.cookie(csrfTokenCookieConfig.name, csrfTokenVal, {
          httpOnly: csrfTokenCookieConfig.httpOnly,
          sameSite: csrfTokenCookieConfig.sameSite,
          secure: csrfTokenCookieConfig.secure,
          path: csrfTokenCookieConfig.path,
          domain: csrfTokenCookieConfig.domain
        })
        this.logger.debug(
          `CSRF Middleware - CSRF token (${csrfTokenCookieConfig.name}) set for client: ${csrfTokenVal}`
        )
      } else {
        this.logger.warn(`CSRF Middleware - req.csrfToken() did not return a token for path: ${req.path}`)
      }

      next()
    })
  }

  private csrfTokenExtractor(req: Request): string {
    this.logger.debug(`CSRF Extractor - Attempting to extract token for: ${req.method} ${req.path}`)
    const tokenFromHeader = req.headers[SecurityHeaders.CSRF_TOKEN_HEADER.toLowerCase()] || req.headers['x-csrf-token']
    const tokenFromBodyOrQuery = req.body?._csrf || req.query?._csrf

    let token = tokenFromHeader || tokenFromBodyOrQuery

    if (Array.isArray(token)) {
      token = token[0]
    }
    this.logger.debug(`CSRF Extractor - Token found in request (presence): ${!!token}`)
    return (token as string) || ''
  }
}
