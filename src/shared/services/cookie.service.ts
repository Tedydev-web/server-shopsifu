import { Injectable, Logger } from '@nestjs/common'
import { Response } from 'express'
import { ConfigService } from '@nestjs/config'
import { ICookieService, CookieConfig } from 'src/routes/auth/auth.types'
import { GlobalError } from '../global.error'

@Injectable()
export class CookieService implements ICookieService {
  private readonly logger = new Logger(CookieService.name)

  constructor(private readonly configService: ConfigService) {}

  private setCookie(res: Response, name: string, value: string, config: Omit<CookieConfig, 'name'>): void {
    const { path, domain, maxAge, httpOnly, secure, sameSite } = config

    res.cookie(name, value, {
      path,
      domain,
      maxAge,
      httpOnly,
      secure,
      sameSite
    })
  }

  private clearCookie(res: Response, name: string, path?: string, domain?: string): void {
    const baseOptions = this.getBaseCookieOptions(name)

    res.clearCookie(name, {
      path: path || baseOptions.path,
      domain: domain || baseOptions.domain,
      httpOnly: baseOptions.httpOnly,
      secure: baseOptions.secure,
      sameSite: baseOptions.sameSite
    })
  }

  setAccessTokenCookie(res: Response, accessToken: string): void {
    const config = this.getCookieConfig('accessToken')
    this.setCookie(res, config.name, accessToken, config.options)
  }

  setRefreshTokenCookie(res: Response, refreshToken: string, rememberMe?: boolean): void {
    const config = this.getCookieConfig('refreshToken')
    let { maxAge } = config.options

    if (rememberMe === false) {
      maxAge = this.configService.get<number>('timeInMs.refreshToken')
    } else if (rememberMe === true) {
      maxAge = this.configService.get<number>('timeInMs.rememberMeRefreshToken')
    }

    this.setCookie(res, config.name, refreshToken, { ...config.options, maxAge })
  }

  clearAccessTokenCookie(res: Response): void {
    const config = this.getCookieConfig('accessToken')
    this.clearCookie(res, config.name, config.options.path, config.options.domain)
  }

  clearRefreshTokenCookie(res: Response): void {
    const config = this.getCookieConfig('refreshToken')
    this.clearCookie(res, config.name, config.options.path, config.options.domain)
  }

  setCsrfCookie(res: Response, csrfToken: string): void {
    const config = this.getCookieConfig('csrfToken')
    // CSRF cookie không có maxAge, nó là session cookie
    this.setCookie(res, config.name, csrfToken, { ...config.options, maxAge: undefined })
  }

  setTokenCookies(res: Response, accessToken: string, refreshToken: string, rememberMe?: boolean): void {
    this.setAccessTokenCookie(res, accessToken)
    this.setRefreshTokenCookie(res, refreshToken, rememberMe)
  }

  clearTokenCookies(res: Response): void {
    this.clearAccessTokenCookie(res)
    this.clearRefreshTokenCookie(res)
  }

  setSltCookie(res: Response, sltToken: string): void {
    const config = this.getCookieConfig('slt')

    if (!sltToken || sltToken.trim() === '') {
      return
    }

    this.setCookie(res, config.name, sltToken, config.options)
  }

  clearSltCookie(res: Response): void {
    const config = this.getCookieConfig('slt')
    this.clearCookie(res, config.name, config.options.path, config.options.domain)
  }

  setOAuthNonceCookie(res: Response, nonce: string): void {
    const config = this.getCookieConfig('oauthNonce')
    this.setCookie(res, config.name, nonce, config.options)
  }

  clearOAuthNonceCookie(res: Response): void {
    const config = this.getCookieConfig('oauthNonce')
    this.clearCookie(res, config.name, config.options.path, config.options.domain)
  }

  setOAuthPendingLinkTokenCookie(res: Response, token: string): void {
    const config = this.getCookieConfig('oauthPendingLink')
    this.setCookie(res, config.name, token, config.options)
  }

  clearOAuthPendingLinkTokenCookie(res: Response): void {
    const config = this.getCookieConfig('oauthPendingLink')
    this.clearCookie(res, config.name, config.options.path, config.options.domain)
  }

  private getCookieConfig(cookieKey: string): { name: string; options: CookieConfig } {
    const config = this.configService.get<{ name: string; options: CookieConfig }>(`cookie.${cookieKey}`)
    if (!config || !config.name || !config.options) {
      throw GlobalError.InternalServerError('auth.error.cookieConfigMissing', { cookieKey })
    }
    return { name: config.name, options: { ...config.options, path: config.options.path || '/' } }
  }

  private getBaseCookieOptions(name: string): Partial<CookieConfig> {
    // Dựa vào name để tìm key trong cấu hình
    const cookieKey = Object.keys(this.configService.get('cookie')).find(
      (key) => this.configService.get(`cookie.${key}.name`) === name
    )
    if (cookieKey) {
      const config = this.getCookieConfig(cookieKey)
      return config.options
    }

    // Fallback nếu không tìm thấy, mặc dù không nên xảy ra
    return {
      path: '/',
      httpOnly: true,
      secure: this.configService.get('isProduction'),
      sameSite: this.configService.get('isProduction') ? 'strict' : 'none'
    }
  }
}
