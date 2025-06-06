import { Injectable, NestMiddleware, Inject, Logger, HttpStatus } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import csurf from 'csurf'
import { ConfigService } from '@nestjs/config'
import { COOKIE_SERVICE } from 'src/shared/constants/injection.tokens'
import { ICookieService, CookieConfig } from 'src/routes/auth/shared/auth.types'
import { v4 as uuidv4 } from 'uuid'
import { SecurityHeaders } from '../../routes/auth/shared/constants/auth.constants'

@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  private readonly logger = new Logger(CsrfMiddleware.name)
  constructor(
    private readonly configService: ConfigService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService
  ) {}

  use(req: Request, res: Response, next: NextFunction) {
    const secret = this.configService.get<string>('COOKIE_SECRET')
    if (!secret) {
      this.logger.error('COOKIE_SECRET is not defined. CSRF protection might not work as expected.')
      // Decide if you want to throw an error or proceed with caution
      // throw new Error('COOKIE_SECRET is not defined for CSRF protection.');
    }

    // Lấy cấu hình cho cookie mà csurf sẽ sử dụng (thường là _csrf)
    const csurfInternalCookieOptions = this.configService.get<CookieConfig>('cookie.csrfSecret')
    if (!csurfInternalCookieOptions) {
      this.logger.error('cookie.csrfSecret is not defined. CSRF protection might use default cookie settings.')
    }

    const csurfOptions: any = {
      cookie: csurfInternalCookieOptions
        ? {
            key: csurfInternalCookieOptions.name || '_csrf',
            path: csurfInternalCookieOptions.path || '/',
            httpOnly: csurfInternalCookieOptions.httpOnly !== undefined ? csurfInternalCookieOptions.httpOnly : true,
            secure:
              csurfInternalCookieOptions.secure !== undefined
                ? csurfInternalCookieOptions.secure
                : this.configService.get('NODE_ENV') === 'production',
            sameSite: csurfInternalCookieOptions.sameSite || 'lax',
            maxAge: csurfInternalCookieOptions.maxAge || undefined, // Hoặc một giá trị mặc định phù hợp
            signed: true // Cookie này NÊN được signed
          }
        : true, // Fallback to csurf defaults if no specific config
      // Kiểm tra cả hai loại header để tương thích tốt hơn
      value: (req: Request) => {
        // Ưu tiên kiểm tra header x-csrf-token (tiêu chuẩn phổ biến)
        const csrfToken = req.headers['x-csrf-token'] as string
        if (csrfToken) {
          return csrfToken
        }
        // Nếu không có, kiểm tra x-xsrf-token (cũng được sử dụng phổ biến)
        return req.headers['x-xsrf-token'] as string
      }
    }

    const csrfProtection = csurf(csurfOptions)

    // Sử dụng void để chỉ ra rằng chúng ta không quan tâm đến Promise trả về (nếu có)
    void csrfProtection(req, res, (err: any) => {
      if (err) {
        this.logger.warn(`CSRF Error: ${err.code} for request to ${req.originalUrl}`)
        // Can customize error response here
        return res
          .status(HttpStatus.FORBIDDEN)
          .json({ message: 'Invalid CSRF token', code: err.code, errorId: uuidv4() })
      }

      // Nếu CSRF hợp lệ, set cookie XSRF-TOKEN cho client đọc
      const clientCsrfTokenCookie = this.configService.get<CookieConfig>('cookie.csrfToken')
      if (!clientCsrfTokenCookie) {
        this.logger.error(
          'cookie.csrfToken is not defined. Client-side XSRF-TOKEN cookie will not be set explicitly by middleware.'
        )
      } else {
        const token = req.csrfToken()
        // Using the cookieService to set the cookie ensures consistency with other cookie operations
        // However, cookieService.setTokenCookies is for auth tokens. We need a generic way or set directly.
        // For now, setting directly, but consider a generic cookie setter in CookieService if needed.
        res.cookie(clientCsrfTokenCookie.name, token, {
          path: clientCsrfTokenCookie.path || '/',
          httpOnly: clientCsrfTokenCookie.httpOnly !== undefined ? clientCsrfTokenCookie.httpOnly : false, // Must be false for client script access
          secure:
            clientCsrfTokenCookie.secure !== undefined
              ? clientCsrfTokenCookie.secure
              : this.configService.get('NODE_ENV') === 'production',
          sameSite: clientCsrfTokenCookie.sameSite || 'lax',
          maxAge: clientCsrfTokenCookie.maxAge // Let it be session cookie if maxAge is not set
        })

        // Đặt cả hai header xsrf-token và x-csrf-token để đảm bảo khả năng tương thích
        res.header(SecurityHeaders.XSRF_TOKEN_HEADER, token)
        res.header(SecurityHeaders.CSRF_TOKEN_HEADER, token)
      }
      next()
    })
  }
}
