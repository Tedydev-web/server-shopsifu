import { Injectable, Logger } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import envConfig from 'src/shared/config'
import {
  AccessTokenPayload,
  AccessTokenPayloadCreate,
  RefreshTokenPayload,
  RefreshTokenPayloadCreate
} from 'src/shared/types/jwt.type'
import { v4 as uuidv4 } from 'uuid'
import { Request, Response, CookieOptions } from 'express'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { PrismaService } from './prisma.service'
import { addMilliseconds } from 'date-fns'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { Prisma, PrismaClient } from '@prisma/client'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { UnauthorizedAccessException } from 'src/routes/auth/auth.error'

type PrismaTransactionClient = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

/**
 * Dịch vụ quản lý token - phụ trách tạo, xác thực, và lưu trữ token
 * Phiên bản được cải thiện tuân thủ best practices:
 * - Quản lý vòng đời đầy đủ của token
 * - Logging chi tiết và nhất quán
 * - JSDoc đầy đủ cho tất cả phương thức
 * - Sử dụng cấu hình tập trung từ envConfig
 */
@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name)

  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService,
    private readonly authRepository: AuthRepository
  ) {}

  /**
   * Tạo và ký access token
   * @param payload Dữ liệu cần nhúng vào token
   * @returns Chuỗi JWT đã ký
   */
  signAccessToken(payload: AccessTokenPayloadCreate) {
    this.logger.debug(`Signing access token for user ${payload.userId}`)
    return this.jwtService.sign(
      { ...payload, uuid: uuidv4() },
      {
        secret: envConfig.ACCESS_TOKEN_SECRET,
        expiresIn: envConfig.ACCESS_TOKEN_EXPIRES_IN,
        algorithm: 'HS256'
      }
    )
  }

  /**
   * Tạo và ký refresh token
   * @param payload Dữ liệu cần nhúng vào token
   * @returns Chuỗi JWT đã ký
   */
  signRefreshToken(payload: RefreshTokenPayloadCreate) {
    this.logger.debug(`Signing refresh token for user ${payload.userId}`)
    return this.jwtService.sign(
      { ...payload, uuid: uuidv4() },
      {
        secret: envConfig.REFRESH_TOKEN_SECRET,
        expiresIn: envConfig.REFRESH_TOKEN_EXPIRES_IN,
        algorithm: 'HS256'
      }
    )
  }

  /**
   * Tạo và ký access token với thời hạn ngắn (10 giây)
   * Chỉ dùng cho mục đích thử nghiệm
   * @param payload Dữ liệu cần nhúng vào token
   * @returns Chuỗi JWT đã ký có thời hạn 10 giây
   */
  signShortLivedToken(payload: AccessTokenPayloadCreate) {
    this.logger.debug(`Signing short-lived access token for testing purposes: userId=${payload.userId}`)
    return this.jwtService.sign(
      { ...payload, uuid: uuidv4() },
      {
        secret: envConfig.ACCESS_TOKEN_SECRET,
        expiresIn: '10s',
        algorithm: 'HS256'
      }
    )
  }

  /**
   * Xác thực access token
   * @param token Chuỗi JWT cần xác thực
   * @returns Payload đã giải mã
   */
  verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    return this.jwtService.verifyAsync(token, {
      secret: envConfig.ACCESS_TOKEN_SECRET
    })
  }

  /**
   * Xác thực refresh token
   * @param token Chuỗi JWT cần xác thực
   * @returns Payload đã giải mã
   */
  verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    return this.jwtService.verifyAsync(token, {
      secret: envConfig.REFRESH_TOKEN_SECRET
    })
  }

  /**
   * Trích xuất access token từ request (cookie hoặc header)
   * @param req Request object
   * @returns Token nếu tìm thấy, null nếu không
   */
  extractTokenFromRequest(req: Request): string | null {
    return req.cookies?.[envConfig.cookie.accessToken.name] || this.extractTokenFromHeader(req)
  }

  /**
   * Trích xuất refresh token từ request (cookie hoặc body)
   * @param req Request object
   * @returns Token nếu tìm thấy, null nếu không
   */
  extractRefreshTokenFromRequest(req: Request): string | null {
    return req.cookies?.[envConfig.cookie.refreshToken.name] || req.body?.refreshToken
  }

  /**
   * Đặt cookies cho access token và refresh token
   * @param res Response object
   * @param accessToken Access token
   * @param refreshToken Refresh token
   * @param maxAgeForRefreshTokenCookie Thời gian sống của refresh token cookie (tùy chọn)
   */
  setTokenCookies(res: Response, accessToken: string, refreshToken: string, maxAgeForRefreshTokenCookie?: number) {
    const accessTokenConfig = envConfig.cookie.accessToken
    const refreshTokenConfig = envConfig.cookie.refreshToken

    const actualRefreshTokenMaxAge = maxAgeForRefreshTokenCookie ?? refreshTokenConfig.maxAge

    if (accessToken && accessTokenConfig.maxAge > 0) {
      res.cookie(accessTokenConfig.name, accessToken, {
        path: accessTokenConfig.path,
        domain: accessTokenConfig.domain,
        maxAge: accessTokenConfig.maxAge,
        httpOnly: accessTokenConfig.httpOnly,
        secure: accessTokenConfig.secure,
        sameSite: accessTokenConfig.sameSite
      })
      this.logger.debug('Access token cookie set successfully')
    } else {
      this.logger.warn(
        'res.cookie SKIPPED for access_token. Reason:',
        !accessToken ? 'AccessToken missing' : 'MaxAge not positive'
      )
    }

    if (refreshToken && actualRefreshTokenMaxAge > 0) {
      res.cookie(refreshTokenConfig.name, refreshToken, {
        path: refreshTokenConfig.path,
        domain: refreshTokenConfig.domain,
        maxAge: actualRefreshTokenMaxAge,
        httpOnly: refreshTokenConfig.httpOnly,
        secure: refreshTokenConfig.secure,
        sameSite: refreshTokenConfig.sameSite
      })
      this.logger.debug('Refresh token cookie set successfully with maxAge:', actualRefreshTokenMaxAge)
    } else {
      this.logger.warn(
        'res.cookie SKIPPED for refresh_token. Reason:',
        !refreshToken ? 'RefreshToken missing' : 'MaxAge not positive'
      )
    }
  }

  /**
   * Xóa tất cả token cookies
   * @param res Response object
   */
  clearTokenCookies(res: Response) {
    const accessTokenConfig = envConfig.cookie.accessToken
    const refreshTokenConfig = envConfig.cookie.refreshToken
    const csrfTokenConfig = envConfig.cookie.csrfToken

    res.clearCookie(accessTokenConfig.name, {
      domain: accessTokenConfig.domain,
      path: accessTokenConfig.path,
      httpOnly: accessTokenConfig.httpOnly,
      secure: accessTokenConfig.secure,
      sameSite: accessTokenConfig.sameSite
    })

    res.clearCookie(refreshTokenConfig.name, {
      domain: refreshTokenConfig.domain,
      path: refreshTokenConfig.path,
      httpOnly: refreshTokenConfig.httpOnly,
      secure: refreshTokenConfig.secure,
      sameSite: refreshTokenConfig.sameSite
    })

    // Also clear CSRF token for client
    res.clearCookie(csrfTokenConfig.name, {
      domain: csrfTokenConfig.domain,
      path: csrfTokenConfig.path,
      httpOnly: csrfTokenConfig.httpOnly,
      secure: csrfTokenConfig.secure,
      sameSite: csrfTokenConfig.sameSite
    })

    this.logger.debug('All token cookies cleared successfully')
  }

  /**
   * Trích xuất token từ Authorization header
   * @private
   * @param req Request object
   * @returns Token nếu tìm thấy, null nếu không
   */
  private extractTokenFromHeader(req: Request): string | null {
    const [type, token] = req.headers.authorization?.split(' ') || []
    return type === 'Bearer' ? token : null
  }

  /**
   * Tạo cặp access token và refresh token mới
   * @param payload Dữ liệu người dùng cần nhúng vào token
   * @param prismaTx Client transaction Prisma (tùy chọn)
   * @param rememberMe Có ghi nhớ đăng nhập không (tùy chọn)
   * @returns Object chứa accessToken, refreshToken và maxAgeForRefreshTokenCookie
   */
  async generateTokens(
    { userId, deviceId, roleId, roleName }: AccessTokenPayloadCreate,
    prismaTx?: PrismaTransactionClient,
    rememberMe?: boolean
  ) {
    this.logger.debug(`Generating tokens for user ${userId}, deviceId ${deviceId}, rememberMe: ${!!rememberMe}`)
    const client = prismaTx || this.prismaService

    const accessToken = this.signAccessToken({
      userId,
      deviceId,
      roleId,
      roleName
    })
    const refreshToken = uuidv4()

    let refreshTokenExpiresInMs: number
    if (rememberMe) {
      refreshTokenExpiresInMs = envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE
    } else {
      refreshTokenExpiresInMs = envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE
    }
    const refreshTokenExpiresAt = addMilliseconds(new Date(), refreshTokenExpiresInMs)

    await this.createRefreshToken(
      {
        token: refreshToken,
        userId,
        deviceId,
        expiresAt: refreshTokenExpiresAt,
        rememberMe: !!rememberMe
      },
      client as any
    )

    return {
      accessToken,
      refreshToken,
      maxAgeForRefreshTokenCookie: refreshTokenExpiresInMs
    }
  }

  /**
   * Tạo refresh token trong cơ sở dữ liệu
   * @param data Dữ liệu refresh token
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Refresh token đã tạo
   */
  async createRefreshToken(
    data: { token: string; userId: number; expiresAt: Date; deviceId: number; rememberMe: boolean },
    tx?: PrismaTransactionClient
  ) {
    this.logger.debug(`Creating refresh token for user ${data.userId}, deviceId ${data.deviceId}`)
    const client = tx || this.prismaService
    return this.authRepository.createRefreshToken(data, client as any)
  }

  /**
   * Đánh dấu refresh token đã được sử dụng
   * @param token Token cần đánh dấu
   * @param tx Client transaction Prisma (tùy chọn)
   */
  async markRefreshTokenUsed(token: string, tx?: PrismaTransactionClient) {
    this.logger.debug(`Marking refresh token as used: ${token.substring(0, 8)}...`)
    const client = tx || this.prismaService
    try {
      await client.refreshToken.update({
        where: { token },
        data: { used: true }
      })
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        this.logger.warn(`Refresh token ${token.substring(0, 8)}... not found when trying to mark as used`)
        throw UnauthorizedAccessException
      }
      this.logger.error(`Error marking refresh token as used: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Xóa refresh token cụ thể
   * @param token Token cần xóa
   * @param tx Client transaction Prisma (tùy chọn)
   */
  async deleteRefreshToken(token: string, tx?: PrismaTransactionClient) {
    this.logger.debug(`Deleting refresh token: ${token.substring(0, 8)}...`)
    const client = tx || this.prismaService
    await this.authRepository.deleteRefreshToken({ token }, client as any)
  }

  /**
   * Xóa tất cả refresh token của người dùng
   * @param userId ID người dùng
   * @param tx Client transaction Prisma (tùy chọn)
   */
  async deleteAllRefreshTokens(userId: number, tx?: PrismaTransactionClient) {
    this.logger.debug(`Deleting all refresh tokens for user ${userId}`)
    const client = tx || this.prismaService
    await client.refreshToken.deleteMany({
      where: { userId }
    })
  }

  /**
   * Tìm refresh token trong cơ sở dữ liệu kèm thông tin người dùng và thiết bị
   * @param token Token cần tìm
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Refresh token kèm thông tin nếu tìm thấy
   */
  async findRefreshTokenWithUserAndDevice(token: string, tx?: PrismaTransactionClient) {
    this.logger.debug(`Finding refresh token with user and device: ${token.substring(0, 8)}...`)
    const client = tx || this.prismaService
    return client.refreshToken.findUnique({
      where: {
        token,
        used: false,
        expiresAt: {
          gt: new Date()
        }
      },
      include: {
        user: {
          include: {
            role: true
          }
        },
        device: true
      }
    })
  }

  /**
   * Tìm refresh token trong cơ sở dữ liệu
   * @param token Token cần tìm
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Thông tin cơ bản của refresh token nếu tìm thấy
   */
  async findRefreshToken(token: string, tx?: PrismaTransactionClient) {
    this.logger.debug(`Finding refresh token: ${token.substring(0, 8)}...`)
    const client = tx || this.prismaService
    return client.refreshToken.findUnique({
      where: { token },
      select: { userId: true, used: true, expiresAt: true }
    })
  }

  /**
   * Làm mới token một cách tự động mà không cần yêu cầu người dùng đăng nhập lại
   * Được sử dụng bởi TokenRefreshInterceptor để tự động làm mới token khi access token hết hạn
   * @param refreshToken Refresh token đang có
   * @param userAgent User-Agent của request hiện tại
   * @param ip IP của request hiện tại
   * @returns Token mới nếu thành công
   */
  async refreshTokenSilently(
    refreshToken: string,
    userAgent: string,
    ip: string
  ): Promise<{
    accessToken: string
    refreshToken?: string
    maxAgeForRefreshTokenCookie?: number
  } | null> {
    try {
      this.logger.debug('Attempting to silently refresh token')

      // Tìm refresh token trong database
      const existingRefreshToken = await this.findRefreshTokenWithUserAndDevice(refreshToken)

      if (!existingRefreshToken || existingRefreshToken.used || existingRefreshToken.expiresAt <= new Date()) {
        this.logger.debug('Refresh token invalid or expired during silent refresh')
        return null
      }

      // Đánh dấu token đã được sử dụng
      await this.markRefreshTokenUsed(refreshToken)

      // Kiểm tra device
      if (existingRefreshToken.device) {
        // Trong silent refresh, chúng ta có thể thực hiện kiểm tra ít nghiêm ngặt hơn để tăng trải nghiệm người dùng
        // Ví dụ: chỉ kiểm tra phần cơ bản của userAgent thay vì so khớp chính xác
        const userAgentMatch =
          this.basicDeviceFingerprint(existingRefreshToken.device.userAgent) === this.basicDeviceFingerprint(userAgent)

        if (!userAgentMatch) {
          this.logger.debug('Device fingerprint mismatch during silent refresh')
          return null
        }
      } else {
        // Không có device liên kết
        this.logger.debug('No device associated with refresh token during silent refresh')
        return null
      }

      // Tạo access token mới
      const accessToken = this.signAccessToken({
        userId: existingRefreshToken.user.id,
        deviceId: existingRefreshToken.deviceId,
        roleId: existingRefreshToken.user.roleId,
        roleName: existingRefreshToken.user.role.name
      })

      // Tạo refresh token mới (tùy chọn, tùy thuộc vào chiến lược của ứng dụng)
      // Trong nhiều trường hợp, chúng ta có thể không muốn tạo refresh token mới mỗi lần refresh ngầm
      // để tránh nhiều token trong database
      const shouldCreateNewRefreshToken = false // Có thể cấu hình tùy theo nhu cầu
      let newRefreshToken: string | undefined
      let maxAge: number | undefined

      if (shouldCreateNewRefreshToken) {
        const refreshTokenExpiresInMs = existingRefreshToken.rememberMe
          ? envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE
          : envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE

        const refreshTokenExpiresAt = addMilliseconds(new Date(), refreshTokenExpiresInMs)
        newRefreshToken = uuidv4()

        await this.createRefreshToken({
          token: newRefreshToken,
          userId: existingRefreshToken.user.id,
          deviceId: existingRefreshToken.deviceId,
          expiresAt: refreshTokenExpiresAt,
          rememberMe: existingRefreshToken.rememberMe
        })

        maxAge = refreshTokenExpiresInMs
      }

      return {
        accessToken,
        refreshToken: newRefreshToken,
        maxAgeForRefreshTokenCookie: maxAge
      }
    } catch (error) {
      this.logger.error('Error during silent token refresh', error)
      return null
    }
  }

  /**
   * Tạo fingerprint cơ bản từ user agent để so sánh thiết bị
   * Lấy thông tin cơ bản về loại thiết bị và trình duyệt
   * @param userAgent User agent string
   * @returns Fingerprint cơ bản
   */
  private basicDeviceFingerprint(userAgent: string): string {
    if (!userAgent) return 'unknown'

    const isMobile = /mobile|android|iphone|ipad|ipod/i.test(userAgent.toLowerCase())
    const browserMatch = userAgent.match(/(chrome|safari|firefox|edge|opera|trident|msie)\/?\s*([\d.]+)/i)
    const osMatch = userAgent.match(/(windows|mac|linux|android|ios|iphone|ipad)\s*([\d.]*)/i)

    const deviceType = isMobile ? 'mobile' : 'desktop'
    const browser = browserMatch ? browserMatch[1].toLowerCase() : 'unknown'
    const os = osMatch ? osMatch[1].toLowerCase() : 'unknown'

    return `${deviceType}-${os}-${browser}`
  }
}
