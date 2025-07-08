import { Injectable } from '@nestjs/common'
import { doubleCsrf } from 'csrf-csrf'
import { Request, Response } from 'express'
import envConfig from 'src/shared/config'
import { COOKIE_DEFINITIONS } from 'src/shared/constants/cookie.constant'

@Injectable()
export class CSRFService {
  private readonly csrfProtection: any

  constructor() {
    const { invalidCsrfTokenError, generateCsrfToken, validateRequest, doubleCsrfProtection } = doubleCsrf({
      getSecret: () => envConfig.COOKIE_SECRET,
      getSessionIdentifier: (req: Request) => 'csrf',
      cookieName: COOKIE_DEFINITIONS.csrfSecret.name,
      cookieOptions: COOKIE_DEFINITIONS.csrfSecret.options,
      size: 64,
      ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
      getCsrfTokenFromRequest: (req: Request) => {
        return (
          (req.headers['x-csrf-token'] as string) ||
          (req.headers['x-xsrf-token'] as string) ||
          (req.body?.csrfToken as string) ||
          ''
        )
      }
    })

    this.csrfProtection = {
      invalidCsrfTokenError,
      generateCsrfToken,
      validateRequest,
      doubleCsrfProtection
    }
  }

  /**
   * Generate CSRF token for a request
   */
  generateToken(req: Request, res: Response): string {
    return this.csrfProtection.generateCsrfToken(req, res)
  }

  /**
   * Validate CSRF token for a request
   */
  validateToken(req: Request): boolean {
    return this.csrfProtection.validateRequest(req)
  }

  /**
   * Get CSRF protection middleware
   */
  getProtectionMiddleware() {
    return this.csrfProtection.doubleCsrfProtection
  }

  /**
   * Get invalid CSRF token error
   */
  getInvalidTokenError() {
    return this.csrfProtection.invalidCsrfTokenError
  }

  /**
   * Check if request method should be ignored for CSRF protection
   */
  shouldIgnoreMethod(method: string): boolean {
    return ['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())
  }
}
