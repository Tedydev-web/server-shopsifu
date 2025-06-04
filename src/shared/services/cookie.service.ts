import { Injectable, Logger } from '@nestjs/common'
import { Response } from 'express'
import { ConfigService } from '@nestjs/config'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { ICookieService, CookieConfig } from 'src/shared/types/auth.types'
import { TypeOfVerificationCodeType } from 'src/routes/auth/constants/auth.constants'

@Injectable()
export class CookieService implements ICookieService {
  private readonly logger = new Logger(CookieService.name)

  constructor(private readonly configService: ConfigService) {}

  /**
   * Set cookie chung
   */
  private setCookie(
    res: Response,
    name: string,
    value: string,
    config: Omit<CookieConfig, 'name'>,
    effectiveMaxAge?: number
  ): void {
    const { path, domain, maxAge, httpOnly, secure, sameSite } = config
    const finalMaxAge = effectiveMaxAge !== undefined ? effectiveMaxAge : maxAge

    this.logger.debug(
      `Setting cookie ${name} with maxAge ${finalMaxAge}, path: ${path}, domain: ${domain || 'undefined'}, httpOnly: ${httpOnly}, secure: ${secure}, sameSite: ${sameSite}`
    )

    try {
      res.cookie(name, value, {
        path,
        domain,
        maxAge: finalMaxAge,
        httpOnly,
        secure,
        sameSite
      })
      this.logger.debug(`Cookie ${name} set successfully`)
    } catch (error) {
      this.logger.error(`Lỗi khi thiết lập cookie ${name}: ${error.message}`, error.stack)
    }
  }

  /**
   * Clear cookie
   */
  private clearCookie(res: Response, name: string, path?: string, domain?: string): void {
    this.logger.debug(`Clearing cookie ${name} with path: ${path}, domain: ${domain || 'undefined'}`)
    try {
      res.clearCookie(name, {
        path: path || '/',
        domain,
        // Phải giữ các cài đặt khác giống khi set cookie để đảm bảo xóa đúng
        httpOnly: true,
        secure: this.configService.get('cookieConfig.secure', false),
        sameSite: this.configService.get('cookieConfig.sameSite', 'lax')
      })
      this.logger.debug(`Cookie ${name} cleared successfully`)
    } catch (error) {
      this.logger.error(`Lỗi khi xóa cookie ${name}: ${error.message}`, error.stack)
    }
  }

  /**
   * Set token cookies
   */
  setTokenCookies(
    res: Response,
    accessToken: string,
    refreshToken: string,
    maxAgeForRefreshTokenCookie?: number
  ): void {
    // Set access token cookie
    const accessTokenConfig = this.getAccessTokenCookieConfig()
    this.logger.debug(`Setting access token cookie with config: ${JSON.stringify(accessTokenConfig)}`)
    this.setCookie(res, CookieNames.ACCESS_TOKEN, accessToken, accessTokenConfig)

    // Set refresh token cookie
    const refreshTokenConfig = this.getRefreshTokenCookieConfig()
    this.logger.debug(`Setting refresh token cookie with config: ${JSON.stringify(refreshTokenConfig)}`)
    this.setCookie(res, CookieNames.REFRESH_TOKEN, refreshToken, refreshTokenConfig, maxAgeForRefreshTokenCookie)
  }

  /**
   * Clear token cookies
   */
  clearTokenCookies(res: Response): void {
    // Clear access token cookie
    const accessTokenConfig = this.getAccessTokenCookieConfig()
    this.clearCookie(res, CookieNames.ACCESS_TOKEN, accessTokenConfig.path, accessTokenConfig.domain)

    // Clear refresh token cookie
    const refreshTokenConfig = this.getRefreshTokenCookieConfig()
    this.clearCookie(res, CookieNames.REFRESH_TOKEN, refreshTokenConfig.path, refreshTokenConfig.domain)
  }

  /**
   * Set SLT cookie
   */
  setSltCookie(res: Response, sltToken: string, purpose: TypeOfVerificationCodeType): void {
    // Set SLT cookie
    this.logger.debug(`[setSltCookie] Setting SLT cookie for purpose: ${purpose}`)
    const sltConfig = this.getSltCookieConfig()
    this.logger.debug(`[setSltCookie] SLT cookie config: ${JSON.stringify(sltConfig)}`)

    // Kiểm tra token
    if (!sltToken || sltToken.trim() === '') {
      this.logger.error('[setSltCookie] SLT token is empty or invalid!')
      return
    }

    // Log kích thước token
    this.logger.debug(`[setSltCookie] SLT token length: ${sltToken.length}`)

    this.setCookie(res, CookieNames.SLT_TOKEN, sltToken, sltConfig)
  }

  /**
   * Clear SLT cookie
   */
  clearSltCookie(res: Response): void {
    // Clear SLT cookie
    this.logger.debug(`[clearSltCookie] Clearing SLT cookie`)
    const sltConfig = this.getSltCookieConfig()
    this.clearCookie(res, CookieNames.SLT_TOKEN, sltConfig.path, sltConfig.domain)
  }

  /**
   * Set OAuth nonce cookie
   */
  setOAuthNonceCookie(res: Response, nonce: string): void {
    // Set OAuth nonce cookie
    const config = this.getOAuthNonceCookieConfig()
    this.setCookie(res, config.name, nonce, config)
    this.logger.debug(`Cookie ${CookieNames.OAUTH_NONCE} set successfully with config: ${JSON.stringify(config)}`)
  }

  /**
   * Clear OAuth nonce cookie
   */
  clearOAuthNonceCookie(res: Response): void {
    // Clear OAuth nonce cookie
    const oauthNonceConfig = this.getOAuthNonceCookieConfig()
    this.clearCookie(res, CookieNames.OAUTH_NONCE, oauthNonceConfig.path, oauthNonceConfig.domain)
  }

  /**
   * Set OAuth pending link token cookie
   */
  setOAuthPendingLinkTokenCookie(res: Response, token: string): void {
    // Set OAuth pending link token cookie
    const config = this.getOAuthPendingLinkTokenCookieConfig()
    this.setCookie(res, config.name, token, config)
    this.logger.debug(
      `Cookie ${CookieNames.OAUTH_PENDING_LINK} set successfully with config: ${JSON.stringify(config)}`
    )
  }

  /**
   * Clear OAuth pending link token cookie
   */
  clearOAuthPendingLinkTokenCookie(res: Response): void {
    // Clear OAuth pending link token cookie
    const config = this.getOAuthPendingLinkTokenCookieConfig()
    this.clearCookie(res, config.name, config.path, config.domain)
    this.logger.debug(`Cookie ${config.name} cleared successfully`)
  }

  private getAccessTokenCookieConfig(): CookieConfig {
    const cookieConfig = this.configService.get<CookieConfig>('cookie.accessToken')

    // Kiểm tra kỹ xem cookie config có đúng không
    if (!cookieConfig) {
      this.logger.warn(
        '[getAccessTokenCookieConfig] Không thể truy cập cấu hình cookie.accessToken, sử dụng giá trị mặc định'
      )

      // Log cấu hình để debug
      const allCookieConfig = this.configService.get('cookie')
    }

    const config = cookieConfig || {
      name: CookieNames.ACCESS_TOKEN,
      path: '/',
      domain: undefined,
      maxAge: 15 * 60 * 1000, // 15 phút
      httpOnly: true,
      secure: false,
      sameSite: 'lax'
    }

    this.logger.debug(`[getAccessTokenCookieConfig] Using config: ${JSON.stringify(config)}`)
    return config
  }

  private getRefreshTokenCookieConfig(): CookieConfig {
    const cookieConfig = this.configService.get<CookieConfig>('cookie.refreshToken')

    if (!cookieConfig) {
      this.logger.warn(
        '[getRefreshTokenCookieConfig] Không thể truy cập cấu hình cookie.refreshToken, sử dụng giá trị mặc định'
      )
    }

    const config = cookieConfig || {
      name: CookieNames.REFRESH_TOKEN,
      path: '/',
      domain: undefined,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
      httpOnly: true,
      secure: false,
      sameSite: 'lax'
    }

    this.logger.debug(`[getRefreshTokenCookieConfig] Using config: ${JSON.stringify(config)}`)
    return config
  }

  private getSltCookieConfig(): CookieConfig {
    const cookieConfig = this.configService.get<CookieConfig>('cookie.slt')

    if (!cookieConfig) {
      this.logger.warn('[getSltCookieConfig] Không thể truy cập cấu hình cookie.slt, sử dụng giá trị mặc định')
    }

    const config = cookieConfig || {
      name: CookieNames.SLT_TOKEN,
      path: '/',
      domain: undefined,
      maxAge: 5 * 60 * 1000, // 5 phút
      httpOnly: true,
      secure: false,
      sameSite: 'lax'
    }

    this.logger.debug(`[getSltCookieConfig] Using config: ${JSON.stringify(config)}`)
    return config
  }

  private getOAuthNonceCookieConfig(): CookieConfig {
    return {
      name: CookieNames.OAUTH_NONCE,
      path: '/',
      domain: undefined,
      maxAge: 15 * 60 * 1000, // 15 phút
      httpOnly: true,
      secure: this.configService.get('cookieConfig.secure', false),
      sameSite: this.configService.get('cookieConfig.sameSite', 'lax')
    }
  }

  private getOAuthPendingLinkTokenCookieConfig(): CookieConfig {
    return {
      name: CookieNames.OAUTH_PENDING_LINK,
      path: '/',
      domain: undefined,
      maxAge: 15 * 60 * 1000, // 15 phút
      httpOnly: true,
      secure: this.configService.get('cookieConfig.secure', false),
      sameSite: this.configService.get('cookieConfig.sameSite', 'lax')
    }
  }
}
