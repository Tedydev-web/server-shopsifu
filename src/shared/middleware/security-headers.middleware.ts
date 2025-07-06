import { Injectable, NestMiddleware } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Request, Response, NextFunction } from 'express'
import { EnvConfigType } from 'src/shared/config'

@Injectable()
export class SecurityHeadersMiddleware implements NestMiddleware {
  constructor(private readonly configService: ConfigService<EnvConfigType>) {}

  use(req: Request, res: Response, next: NextFunction) {
    // Chống tấn công XSS
    res.setHeader('X-XSS-Protection', '1; mode=block')

    // Ngăn trình duyệt tự động suy luận kiểu MIME
    res.setHeader('X-Content-Type-Options', 'nosniff')

    // Chống tấn công Clickjacking
    res.setHeader('X-Frame-Options', 'DENY')

    // Buộc sử dụng HTTPS
    if (this.configService.get('isProd')) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
    }

    // Kiểm soát cache
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')

    // Kiểm soát Referrer
    res.setHeader('Referrer-Policy', 'no-referrer')

    // Chính sách bảo mật nội dung (CSP) - Cấu hình cơ bản, có thể tùy chỉnh thêm
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    )

    next()
  }
}
