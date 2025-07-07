import { Injectable, NestMiddleware, Logger } from '@nestjs/common'
import { Request, Response, NextFunction, RequestHandler } from 'express'
import csurf from 'csurf'
import { CookieService } from '../services/cookie.service'
import envConfig from 'src/shared/config'

@Injectable()
export class CsrfProtectionMiddleware implements NestMiddleware {
  private readonly logger = new Logger(CsrfProtectionMiddleware.name)
  private readonly csurfProtection: RequestHandler

  constructor(private readonly cookieService: CookieService) {
    // Lấy cấu hình chi tiết cho cookie bí mật (_csrf) từ config trung tâm
    const csrfSecretConfig = {
      name: envConfig.CSRF_HEADER_NAME,
      options: {
        httpOnly: true,
        secure: envConfig.NODE_ENV !== 'production',
        sameSite: 'lax' as const
      },
      value: (req: Request) => {
        return (req.headers['x-csrf-token'] || req.headers['x-xsrf-token']) as string
      }
    }

    this.csurfProtection = csurf({
      cookie: {
        ...csrfSecretConfig.options,
        // Cấu hình của csurf yêu cầu `signed` và `key` phải được đặt ở đây
        signed: true,
        key: csrfSecretConfig.name
      },
      value: (req: Request) => {
        // Hỗ trợ cả hai header phổ biến mà các framework frontend hay dùng
        return (req.headers['x-csrf-token'] || req.headers['x-xsrf-token']) as string
      }
    })
  }

  use(req: Request, res: Response, next: NextFunction) {
    void this.csurfProtection(req, res, (err: any) => {
      if (err) {
        this.logger.warn(`Invalid CSRF token: ${err.code}`, { url: req.originalUrl })
        // Để cho AllExceptionsFilter xử lý lỗi một cách nhất quán
        return next(err)
      }
      const token = req.csrfToken()
      // Sử dụng CookieService để set cookie XSRF-TOKEN cho client
      this.cookieService.set(res, 'csrfToken', token)

      next()
    })
  }
}
