import { Injectable, NestMiddleware, Logger, ForbiddenException } from '@nestjs/common'
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
        const tokenFromHeader =
          (req.headers['x-xsrf-token'] as string) ||
          (req.headers['x-csrf-token'] as string) ||
          (req.headers['X-CSRF-Token'] as string)
        if (tokenFromHeader) {
          return tokenFromHeader
        }
        const tokenFromBody = req.body?._csrf as string
        return tokenFromBody
      }
    }) as (req: Request, res: Response, next: NextFunction) => void
    this.logger.verbose(
      `CSRF Middleware initialized. CSRF Secret Cookie Name: ${envConfig.cookie.csrfSecretCookie.name}, signed: true, XSRF-TOKEN Cookie Name: ${envConfig.cookie.csrfToken.name}`
    )
  }

  use(req: Request, res: Response, next: NextFunction) {
    this.logger.debug(`[CsrfMiddleware ENTRY] Path: ${req.path}`)
    this.logger.debug(`[CsrfMiddleware ENTRY] Cookies: ${JSON.stringify(req.cookies)}`)
    this.logger.debug(`[CsrfMiddleware ENTRY] Signed Cookies: ${JSON.stringify(req.signedCookies)}`)
    this.logger.debug(
      `[CsrfMiddleware ENTRY] Headers: x-csrf-token: ${req.headers['x-csrf-token'] || 'N/A'}, x-xsrf-token: ${req.headers['x-xsrf-token'] || 'N/A'}`
    )

    this.logger.debug(`CSRF Middleware - Incoming request: ${req.method} ${req.path}`)

    if (
      req.path.startsWith('/api/v1/auth/google/callback') ||
      req.path.startsWith('/api/v1/webhook') ||
      req.path.startsWith('/api/v1/health')
    ) {
      this.logger.debug(`CSRF Middleware - Bypassing for specific path: ${req.path}`)
      return next()
    }

    this.csrfProtection(req, res, (err?: any) => {
      if (err) {
        this.logger.error(`CSRF Protection Error for path ${req.path}: ${err.code} - ${err.message}`, err.stack)
        // Để AllExceptionsFilter xử lý lỗi này một cách nhất quán
        return next(new ForbiddenException(`Invalid CSRF token: ${err.code || 'UNKNOWN_CSRF_ERROR'}`))
      }

      const csrfTokenToSet = req.csrfToken?.()
      if (csrfTokenToSet && envConfig.cookie.csrfToken.name) {
        const currentXsrfToken = req.cookies?.[envConfig.cookie.csrfToken.name]
        // Chỉ set cookie xsrf-token nếu nó chưa có hoặc thay đổi,
        // hoặc nếu response chưa set cookie này (để tránh set lại nhiều lần không cần thiết)
        // Điều này quan trọng vì một số trình duyệt/client có thể không thích việc cookie được set lại liên tục.
        if (
          currentXsrfToken !== csrfTokenToSet ||
          !res.getHeader('Set-Cookie')?.toString().includes(envConfig.cookie.csrfToken.name)
        ) {
          res.cookie(envConfig.cookie.csrfToken.name, csrfTokenToSet, {
            path: envConfig.cookie.csrfToken.path,
            secure: envConfig.cookie.csrfToken.secure,
            sameSite: envConfig.cookie.csrfToken.sameSite as 'strict' | 'lax' | 'none' | boolean,
            httpOnly: envConfig.cookie.csrfToken.httpOnly, // Usually false for client retrieval
            domain: envConfig.cookie.csrfToken.domain
            // maxAge is typically not set here, relying on session or _csrf cookie lifetime
          })
          this.logger.debug(
            `XSRF-TOKEN cookie ("${envConfig.cookie.csrfToken.name}") set/updated by CSRF middleware with value: ${csrfTokenToSet}`
          )
        }
      } else if (!csrfTokenToSet) {
        this.logger.warn(
          `req.csrfToken() did not return a value for path ${req.path}. XSRF-TOKEN cookie might not be set.`
        )
      }
      next()
    })
  }
}
