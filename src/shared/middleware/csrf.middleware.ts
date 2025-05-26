import { Injectable, NestMiddleware, Logger } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import csrf from 'csurf'
import envConfig from 'src/shared/config'
import { SecurityHeaders } from '../constants/auth.constant'

@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  private readonly logger = new Logger(CsrfMiddleware.name)
  private csrfProtection: (req: Request, res: Response, next: NextFunction) => void

  constructor() {
    const csrfSecretCookieConfig = envConfig.cookie.csrfSecretCookie
    if (!csrfSecretCookieConfig || !csrfSecretCookieConfig.name) {
      this.logger.error('CSRF secret cookie configuration or name is missing in envConfig.cookie')
      throw new Error('CSRF secret cookie configuration error')
    }
    if (!envConfig.COOKIE_SECRET) {
      this.logger.error('COOKIE_SECRET is not defined in envConfig. Cannot initialize CSRF protection.')
      throw new Error('COOKIE_SECRET is not defined for CSRF protection')
    }
    if (!envConfig.cookie.csrfToken || !envConfig.cookie.csrfToken.name) {
      this.logger.error('CSRF token cookie configuration or name is missing in envConfig.cookie.csrfToken')
      throw new Error('CSRF token cookie configuration error')
    }

    this.csrfProtection = csrf({
      cookie: {
        key: envConfig.cookie.csrfSecretCookie.name,
        path: envConfig.cookie.csrfSecretCookie.path,
        httpOnly: envConfig.cookie.csrfSecretCookie.httpOnly,
        secure: envConfig.cookie.csrfSecretCookie.secure,
        sameSite: envConfig.cookie.csrfSecretCookie.sameSite as 'strict' | 'lax' | 'none' | boolean,
        domain: envConfig.cookie.csrfSecretCookie.domain,
        signed: true
      },
      value: (req: Request) => {
        const token = req.headers['x-csrf-token'] || req.headers['X-CSRF-Token'] || req.body._csrf
        const tokenFromHeader = req.headers['x-xsrf-token'] as string
        const tokenFromBody = req.body?._csrf as string // if forms are used with _csrf field
        return tokenFromHeader || tokenFromBody
      }
    }) as (req: Request, res: Response, next: NextFunction) => void
    this.logger.verbose(
      `CSRF Middleware initialized. CSRF Secret Cookie Name: ${envConfig.cookie.csrfSecretCookie.name}, CSRF Token Cookie Name: ${envConfig.cookie.csrfToken.name}` // Đã sửa
    )
  }

  use(req: Request, res: Response, next: NextFunction) {
    this.logger.debug(`[CsrfMiddleware ENTRY] Cookies: ${JSON.stringify(req.cookies)}`)
    this.logger.debug(`[CsrfMiddleware ENTRY] Signed Cookies: ${JSON.stringify(req.signedCookies)}`)

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
        this.logger.warn(`CSRF Error: ${err.code} - ${err.message} for ${req.method} ${req.originalUrl}`)
        // Gửi lỗi CSRF chuẩn
        return res.status(403).json({ message: 'Invalid CSRF token', code: err.code || 'EBADCSRFTOKEN' })
      }

      this.logger.debug(
        `CSRF Protection Executed. Tokens: req.csrfToken()=${req.csrfToken()}, XSRF-TOKEN Cookie (from client)=${req.cookies?.[envConfig.cookie.csrfToken.name]}, ` +
          `CSRF Secret Cookie (${envConfig.cookie.csrfSecretCookie.name} value from req.signedCookies): ${req.signedCookies?.[envConfig.cookie.csrfSecretCookie.name]}` // Đã sửa
      )

      // Đảm bảo XSRF-TOKEN cookie được gửi cho client nếu nó chưa có hoặc đã thay đổi
      const csrfToken = req.csrfToken()
      const clientXsrfToken = req.cookies?.[envConfig.cookie.csrfToken.name]

      if (csrfToken && csrfToken !== clientXsrfToken) {
        const csrfTokenCookieConfig = envConfig.cookie.csrfToken
        res.cookie(csrfTokenCookieConfig.name, csrfToken, {
          httpOnly: csrfTokenCookieConfig.httpOnly,
          secure: csrfTokenCookieConfig.secure,
          sameSite: csrfTokenCookieConfig.sameSite, // Đã sửa lỗi type ở config.ts
          path: csrfTokenCookieConfig.path,
          domain: csrfTokenCookieConfig.domain
          // Không set maxAge cho XSRF-TOKEN cookie, để nó là session cookie
        })
        this.logger.debug(`XSRF-TOKEN cookie set/updated for client with value: ${csrfToken}`)
      }
      next()
    })
  }
}
