import { Injectable, NestMiddleware, Logger } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import { ConfigService } from '@nestjs/config'
import { SecurityHeaders } from 'src/shared/constants/auth.constant'

@Injectable()
export class SecurityHeadersMiddleware implements NestMiddleware {
  private readonly logger = new Logger(SecurityHeadersMiddleware.name)

  constructor(private readonly configService: ConfigService) {}

  use(req: Request, res: Response, next: NextFunction) {
    // XSS Protection
    res.setHeader(SecurityHeaders.XSS_PROTECTION, '1; mode=block')

    // Prevents MIME-sniffing
    res.setHeader(SecurityHeaders.CONTENT_TYPE_OPTIONS, 'nosniff')

    // Clickjacking protection
    res.setHeader(SecurityHeaders.FRAME_OPTIONS, 'DENY')

    // HSTS - Forces HTTPS
    if (this.configService.get('app.secure', true)) {
      res.setHeader(SecurityHeaders.HSTS, 'max-age=31536000; includeSubDomains; preload')
    }

    // Cache control
    res.setHeader(SecurityHeaders.CACHE_CONTROL, 'no-store, no-cache, must-revalidate, proxy-revalidate')

    // Referrer Policy
    res.setHeader(SecurityHeaders.REFERRER_POLICY, 'no-referrer')

    // Content Security Policy
    if (this.configService.get('security.contentSecurityPolicy.enabled', true)) {
      const cspValue = this.configService.get(
        'security.contentSecurityPolicy.value',
        "default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval';"
      )
      res.setHeader(SecurityHeaders.CONTENT_SECURITY_POLICY, cspValue)
    }

    // Disallow embedding as Flash
    res.setHeader(SecurityHeaders.PERMITTED_CROSS_DOMAIN_POLICIES, 'none')

    // Certificate Transparency
    res.setHeader(SecurityHeaders.EXPECT_CT, 'enforce, max-age=86400')

    next()
  }
}
