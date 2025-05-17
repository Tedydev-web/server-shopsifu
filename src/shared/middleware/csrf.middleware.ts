import { Injectable, NestMiddleware } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import csurf from 'csurf'
import envConfig from '../config'
import { CookieNames, SecurityHeaders } from '../constants/auth.constant'

@Injectable()
export class CsrfMiddleware implements NestMiddleware {
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
    console.log('CSRF Middleware - Incoming request:', req.method, req.path)
    console.log('CSRF Middleware - Headers:', JSON.stringify(req.headers))
    console.log('CSRF Middleware - Cookies before protection:', req.cookies)

    if (
      req.path.startsWith('/api/v1/auth/google/callback') ||
      req.path.startsWith('/api/v1/webhook') ||
      req.path.startsWith('/api/v1/health')
    ) {
      console.log('CSRF Middleware - Bypassing for specific path:', req.path)
      return next()
    }

    this.csrfProtection(req, res, (err: any) => {
      if (err) {
        console.error('CSRF Protection Error:', err.code === 'EBADCSRFTOKEN' ? 'Invalid CSRF token' : err.message, err)
        console.error(
          'CSRF Secret Cookie (_csrfSecret value from req.signedCookies):',
          req.signedCookies?.['_csrfSecret']
        )
        console.error('CSRF Token Cookie (xsrf-token value from req.cookies):', req.cookies?.[CookieNames.CSRF_TOKEN])
        console.error(
          'Header value (X-CSRF-Token from req.headers):',
          req.headers[SecurityHeaders.CSRF_TOKEN_HEADER.toLowerCase()]
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
        console.log(`CSRF Middleware - CSRF token (${CookieNames.CSRF_TOKEN}) set for client:`, csrfTokenVal)
      } else {
        console.warn('CSRF Middleware - req.csrfToken() did not return a token for path:', req.path)
      }

      console.log('CSRF Middleware - Cookies after protection:', req.cookies)
      next()
    })
  }

  private csrfTokenExtractor(req: Request): string {
    console.log(`CSRF Extractor - Attempting to extract token for: ${req.method} ${req.path}`)
    const tokenFromHeader = req.headers[SecurityHeaders.CSRF_TOKEN_HEADER.toLowerCase()] || req.headers['x-csrf-token']
    const tokenFromBodyOrQuery = req.body?._csrf || req.query?._csrf

    let token = tokenFromHeader || tokenFromBodyOrQuery

    if (Array.isArray(token)) {
      token = token[0]
    }
    console.log('CSRF Extractor - Token found in request:', token)
    return (token as string) || ''
  }
}
