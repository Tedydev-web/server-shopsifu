import { Injectable, Logger } from '@nestjs/common'
import { CookieOptions, Response } from 'express'
import { COOKIE_DEFINITIONS, CookieDefinitionKey } from '../constants/cookie.constant'
import ms from 'ms'

@Injectable()
export class CookieService {
  private readonly logger = new Logger(CookieService.name)

  constructor() {}

  /**
   * Phương thức chung để thiết lập bất kỳ cookie nào đã được định nghĩa trong file cấu hình.
   * Tự động xử lý các prefix bảo mật (__Host-) và tất cả các tùy chọn khác.
   * @param res Đối tượng Response của Express.
   * @param key Tên logic của cookie (ví dụ: 'accessToken').
   * @param value Giá trị của cookie.
   * @param options Các tùy chọn bổ sung hoặc ghi đè lên cấu hình mặc định.
   */
  set(res: Response, key: CookieDefinitionKey, value: string, options: Partial<CookieOptions> = {}): void {
    const definition = COOKIE_DEFINITIONS[key]

    if (!definition) {
      this.logger.error(`Không tìm thấy cấu hình cho cookie với key: "${key}".`)
      return
    }

    const cookieName = `${definition.prefix}${definition.name}`
    const finalOptions = { ...definition.options, ...options }

    res.cookie(cookieName, value, finalOptions)
  }

  /**
   * Phương thức chung để xóa bất kỳ cookie nào đã được định nghĩa.
   * @param res Đối tượng Response của Express.
   * @param key Tên logic của cookie cần xóa.
   */
  clear(res: Response, key: CookieDefinitionKey): void {
    const definition = COOKIE_DEFINITIONS[key]
    if (!definition) {
      this.logger.error(`Không tìm thấy cấu hình cho cookie với key: "${key}".`)
      return
    }

    const cookieName = `${definition.prefix}${definition.name}`
    // Để xóa cookie, phải cung cấp chính xác path và domain đã dùng để set.
    const clearOptions: Partial<CookieOptions> = {
      path: definition.options.path
    }
    if ('domain' in definition.options && typeof definition.options.domain === 'string' && definition.options.domain) {
      clearOptions.domain = definition.options.domain
    }
    res.clearCookie(cookieName, clearOptions)
  }

  // --- Các phương thức tiện ích ---

  /**
   * Thiết lập cả hai cookie access và refresh token cùng một lúc.
   */
  setTokenCookies(res: Response, accessToken: string, refreshToken: string, rememberMe: boolean = false): void {
    this.set(res, 'accessToken', accessToken)

    // Áp dụng logic "remember me" cho thời gian sống của refresh token
    const refreshTokenMaxAge = rememberMe
      ? ms(process.env.REFRESH_TOKEN_EXPIRES_IN || '7d')
      : ms(process.env.REFRESH_TOKEN_EXPIRES_IN || '7d')

    this.set(res, 'refreshToken', refreshToken, { maxAge: refreshTokenMaxAge })
  }

  /**
   * Xóa cả hai cookie access và refresh token.
   */
  clearTokenCookies(res: Response): void {
    this.clear(res, 'accessToken')
    this.clear(res, 'refreshToken')
  }
}
