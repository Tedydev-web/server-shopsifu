import { Injectable, NestMiddleware, Logger, HttpStatus } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import csurf from 'csurf'
import { ConfigService } from '@nestjs/config'
import { HttpHeader } from 'src/shared/constants/http.constants'
import { CookieConfig } from 'src/routes/auth/auth.types'

@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  private readonly logger = new Logger(CsrfMiddleware.name)
  constructor(private readonly configService: ConfigService) {}

  use(req: Request, res: Response, next: NextFunction) {
    const csrfSecretCookieOptions = this.configService.get<CookieConfig>('cookie.csrfSecret.options')
    const csrfTokenCookieOptions = this.configService.get<CookieConfig>('cookie.csrfToken.options')

    if (!csrfSecretCookieOptions || !csrfTokenCookieOptions) {
      // Trong môi trường production, nên chặn request thay vì tiếp tục
      if (this.configService.get('isProduction')) {
        return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ message: 'Lỗi cấu hình máy chủ.' })
      }
    }

    const csurfProtection = csurf({
      cookie: {
        ...csrfSecretCookieOptions,
        key: this.configService.get<string>('cookie.csrfSecret.name'),
        signed: true // _csrf cookie luôn phải được signed
      },
      value: (req: Request) => {
        // Hỗ trợ cả hai header phổ biến
        return (req.headers['x-csrf-token'] || req.headers['x-xsrf-token']) as string
      }
    })

    void csurfProtection(req, res, () => {
      const token = req.csrfToken()
      // Set cookie XSRF-TOKEN cho client đọc
      res.cookie(this.configService.get<string>('cookie.csrfToken.name'), token, {
        ...csrfTokenCookieOptions,
        maxAge: undefined // Đây là session cookie, không cần maxAge
      })

      // Đặt cả hai header để client dễ dàng lấy
      res.header(HttpHeader.XSRF_TOKEN_HEADER, token)
      res.header(HttpHeader.CSRF_TOKEN_HEADER, token)

      next()
    })
  }
}
