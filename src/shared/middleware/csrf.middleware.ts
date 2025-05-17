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
        key: CookieNames.CSRF_TOKEN,
        httpOnly: true,
        sameSite: 'strict',
        secure: envConfig.NODE_ENV === 'production',
        path: '/'
      },
      ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
      value: (req: Request) => this.csrfTokenExtractor(req)
    })
  }

  use(req: Request, res: Response, next: NextFunction) {
    // Bỏ qua bảo vệ CSRF cho API endpoints được chỉ định
    // (ví dụ: endpoint callback từ bên thứ ba hoặc webhook)
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

      // Đặt CSRF token vào header response
      const csrfToken = req.csrfToken?.()
      if (csrfToken) {
        res.setHeader(SecurityHeaders.CSRF_TOKEN_HEADER, csrfToken)

        // Cũng có thể đặt vào cookie có thể đọc được từ frontend
        res.cookie(CookieNames.CSRF_TOKEN, csrfToken, {
          httpOnly: false, // Cho phép JavaScript đọc được token
          sameSite: 'strict',
          secure: envConfig.NODE_ENV === 'production',
          path: '/'
        })
      }

      next()
    })
  }

  private csrfTokenExtractor(req: Request): string {
    // Thứ tự ưu tiên: header -> body -> query
    return (
      (req.headers[SecurityHeaders.CSRF_TOKEN_HEADER.toLowerCase()] as string) ||
      req.body?._csrf ||
      (req.query?._csrf as string) ||
      ''
    )
  }
}
