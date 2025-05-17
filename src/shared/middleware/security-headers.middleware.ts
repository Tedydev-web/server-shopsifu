import { Injectable, NestMiddleware } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import { SecurityHeaders } from '../constants/auth.constant'
import envConfig from '../config'

@Injectable()
export class SecurityHeadersMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Content Security Policy
    res.setHeader(
      SecurityHeaders.CONTENT_SECURITY_POLICY,
      "default-src 'self'; script-src 'self'; object-src 'none'; img-src 'self' data:; style-src 'self';"
    )

    // Prevent MIME type sniffing
    res.setHeader(SecurityHeaders.X_CONTENT_TYPE_OPTIONS, 'nosniff')

    // Force HTTPS in production
    if (envConfig.NODE_ENV === 'production') {
      res.setHeader(
        SecurityHeaders.STRICT_TRANSPORT_SECURITY,
        'max-age=31536000; includeSubDomains; preload'
      )
    }

    // Prevent embedding in iframes
    res.setHeader(SecurityHeaders.X_FRAME_OPTIONS, 'DENY')

    // Add XSS protection
    res.setHeader(SecurityHeaders.X_XSS_PROTECTION, '1; mode=block')

    // Set cache control for Auth endpoints
    if (req.path.startsWith('/auth/')) {
      res.setHeader(SecurityHeaders.CACHE_CONTROL, 'no-store, no-cache, must-revalidate, proxy-revalidate')
    }

    next()
  }
} 