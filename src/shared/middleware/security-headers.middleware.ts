import { Injectable, NestMiddleware } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import { SecurityHeaders } from '../constants/auth.constant'
import envConfig from '../config'

@Injectable()
export class SecurityHeadersMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    res.setHeader(
      SecurityHeaders.CONTENT_SECURITY_POLICY,
      "default-src 'self'; script-src 'self'; object-src 'none'; img-src 'self' data:; style-src 'self';"
    )

    res.setHeader(SecurityHeaders.X_CONTENT_TYPE_OPTIONS, 'nosniff')

    if (envConfig.NODE_ENV === 'production') {
      res.setHeader(SecurityHeaders.STRICT_TRANSPORT_SECURITY, 'max-age=31536000; includeSubDomains; preload')
    }

    res.setHeader(SecurityHeaders.X_FRAME_OPTIONS, 'DENY')

    res.setHeader(SecurityHeaders.X_XSS_PROTECTION, '1; mode=block')

    if (req.path.startsWith('/api/v1/auth/')) {
      res.setHeader(SecurityHeaders.CACHE_CONTROL, 'no-store, no-cache, must-revalidate, proxy-revalidate')
    }

    next()
  }
}
