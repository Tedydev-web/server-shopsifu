import { Injectable, NestMiddleware, Logger } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import csurf from 'csurf'
import envConfig from '../config'
import { CookieNames, SecurityHeaders } from '../constants/auth.constant'

@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  private readonly logger = new Logger(CsrfMiddleware.name)
  private readonly csrfProtection: any

  constructor() {
    this.csrfProtection = csurf({
      cookie: {
        key: '_csrfSecret',
        httpOnly: true,
        secure: envConfig.NODE_ENV === 'production',
        sameSite: 'lax',
        signed: true,
        path: '/'
      },
      ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
      value: (req: Request) => this.csrfTokenExtractor(req)
    })
  }

  use(req: Request, res: Response, next: NextFunction) {
    this.logger.debug(`CSRF Middleware - Incoming request: ${req.method} ${req.path}`)
    this.logger.debug(`CSRF Middleware - Headers: ${JSON.stringify(req.headers)}`)
    this.logger.debug(`CSRF Middleware - Cookies before protection: ${JSON.stringify(req.cookies)}`)

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
          `CSRF Secret Cookie (_csrfSecret value from req.signedCookies): ${req.signedCookies?.['_csrfSecret']}`
        )
        this.logger.error(
          `CSRF Token Cookie (xsrf-token value from req.cookies): ${req.cookies?.[CookieNames.CSRF_TOKEN]}`
        )
        this.logger.error(
          `Header value (X-CSRF-Token from req.headers): ${req.headers[SecurityHeaders.CSRF_TOKEN_HEADER.toLowerCase()]}`
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
        res.setHeader(SecurityHeaders.CSRF_TOKEN_HEADER, csrfTokenVal)
        res.cookie(CookieNames.CSRF_TOKEN, csrfTokenVal, {
          httpOnly: false,
          sameSite: 'lax',
          secure: envConfig.NODE_ENV === 'production',
          path: '/',
          signed: false
        })
        this.logger.debug(`CSRF Middleware - CSRF token (${CookieNames.CSRF_TOKEN}) set for client: ${csrfTokenVal}`)
      } else {
        this.logger.warn(`CSRF Middleware - req.csrfToken() did not return a token for path: ${req.path}`)
      }

      this.logger.debug(`CSRF Middleware - Cookies after protection: ${JSON.stringify(req.cookies)}`)
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
    this.logger.debug(`CSRF Extractor - Token found in request: ${token}`)
    return (token as string) || ''
  }
}
