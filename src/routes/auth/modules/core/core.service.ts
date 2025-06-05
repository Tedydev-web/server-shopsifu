import { Injectable, Logger, Inject } from '@nestjs/common'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { v4 as uuidv4 } from 'uuid'
import { Response, Request } from 'express'
import { AuthError } from '../../auth.error'
import { HashingService } from 'src/shared/services/hashing.service'
import { IUserAuthService, ICookieService, ITokenService } from 'src/shared/types/auth.types'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constants'
import { OtpService } from '../../modules/otp/otp.service'
import { User, Device, Role, UserProfile } from '@prisma/client'
import { AccessTokenPayloadCreate } from 'src/shared/types/jwt.type'
import { UserStatus } from '@prisma/client'
import { COOKIE_SERVICE, REDIS_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { UserAuthRepository, DeviceRepository, SessionRepository } from 'src/shared/repositories/auth'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'
import { HttpException } from '@nestjs/common'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'

interface RegisterUserParams {
  email: string
  password: string
  confirmPassword: string
  firstName: string
  lastName: string
  username?: string
  phoneNumber?: string
  ip?: string
  userAgent?: string
}

interface LoginParams {
  emailOrUsername: string
  password: string
  rememberMe?: boolean
  ip?: string
  userAgent?: string
}

@Injectable()
export class CoreService implements IUserAuthService {
  private readonly logger = new Logger(CoreService.name)

  constructor(
    private readonly hashingService: HashingService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly i18nService: I18nService<I18nTranslations>,
    private readonly userAuthRepository: UserAuthRepository,
    private readonly deviceRepository: DeviceRepository,
    private readonly otpService: OtpService,
    private readonly sessionRepository: SessionRepository,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService
  ) {}

  /**
   * Tạo username ngẫu nhiên
   */
  private async generateUniqueUsername(baseUsername: string): Promise<string> {
    // Tạo username cơ bản từ email hoặc tên
    let username = baseUsername
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '')
      .substring(0, 15)

    // Kiểm tra username đã tồn tại chưa
    const exists = await this.userAuthRepository.doesUsernameExist(username)

    // Nếu username đã tồn tại, thêm số ngẫu nhiên
    if (exists) {
      const randomSuffix = Math.floor(Math.random() * 10000)
      username = `${username.substring(0, 10)}${randomSuffix}`
    }

    return username
  }

  /**
   * Hoàn tất đăng ký
   */
  async completeRegistration(params: RegisterUserParams): Promise<void> {
    const { email, password, firstName, lastName, username, phoneNumber, ip, userAgent } = params

    // Kiểm tra email đã tồn tại chưa
    const existingUser = await this.userAuthRepository.findByEmail(email)

    if (existingUser) {
      throw AuthError.EmailAlreadyExists()
    }

    // Kiểm tra số điện thoại nếu có
    if (phoneNumber) {
      const phoneNumberExists = await this.userAuthRepository.doesPhoneNumberExist(phoneNumber)
      if (phoneNumberExists) {
        throw AuthError.PhoneNumberAlreadyExists()
      }
    }

    // Mã hóa mật khẩu
    const hashedPassword = await this.hashingService.hash(password)

    // Tạo username nếu không được cung cấp
    const finalUsername = username || (await this.generateUniqueUsername(email.split('@')[0]))

    // Tạo user mới
    await this.userAuthRepository.createUser({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      username: finalUsername,
      phoneNumber
    })
  }

  /**
   * Validate user credentials
   */
  async validateUser(emailOrUsername: string, password: string): Promise<any> {
    // Tìm user theo email hoặc username
    const user = await this.userAuthRepository.findByEmailOrUsername(emailOrUsername)

    // Kiểm tra user tồn tại
    if (!user) {
      return null
    }

    // Kiểm tra mật khẩu
    const isPasswordValid = await this.hashingService.compare(password, user.password)
    if (!isPasswordValid) {
      return null
    }

    // Loại bỏ mật khẩu trước khi trả về
    const { password: _, ...result } = user
    return result
  }

  /**
   * Đăng nhập
   */
  async login(params: LoginParams, res: Response): Promise<any> {
    const user = await this.validateUser(params.emailOrUsername, params.password)

    if (!user) {
      throw AuthError.InvalidPassword()
    }

    if (user.status === UserStatus.BLOCKED) {
      throw AuthError.AccountLocked()
    }

    if (user.status !== UserStatus.ACTIVE) {
      throw AuthError.AccountNotActive()
    }

    const rememberMe = params.rememberMe ?? false

    let device
    try {
      device = await this.deviceRepository.upsertDevice(
        user.id,
        params.userAgent || 'Unknown',
        params.ip || 'Unknown',
        `Device from ${params.userAgent?.substring(0, 20) || 'Unknown UA'} at ${new Date().toLocaleDateString()}`
      )
    } catch (error) {
      this.logger.error(`[Login] Error upserting device for user ${user.id}: ${error.message}`, error.stack)
      throw AuthError.DeviceProcessingFailed()
    }

    const deviceIsCurrentlyTrusted = await this.deviceRepository.isDeviceTrustValid(device.id)
    const reverifyFlagKey = RedisKeyManager.customKey('device:needs_reverify_after_revoke', device.id.toString())
    const needsReverifyAfterRevokeFlag = await this.redisService.get(reverifyFlagKey)
    const forceReverificationDueToRevoke = needsReverifyAfterRevokeFlag === 'true'

    if (deviceIsCurrentlyTrusted && !forceReverificationDueToRevoke) {
      this.logger.debug(
        `[Login] Device ${device.id} for user ${user.id} is trusted and no pending revoke-reverification. Finalizing login.`
      )
      if (needsReverifyAfterRevokeFlag) {
        // Clear flag if it existed but didn't force reverification (e.g. expired or already handled)
        await this.redisService.del(reverifyFlagKey)
      }
      return this.finalizeLoginAndCreateTokens(
        user,
        device,
        rememberMe,
        res,
        params.ip,
        params.userAgent,
        true /* explicitly trusted */
      )
    }

    // At this point, device is either untrusted OR forceReverificationDueToRevoke is true.
    // Log the reason for proceeding to verification.
    if (forceReverificationDueToRevoke) {
      this.logger.debug(
        `[Login] Device ${device.id} (user ${user.id}) requires reverification due to recent session revoke (forceReverificationDueToRevoke=true).`
      )
      // Flag will be cleared by OtpController/TwoFactorController after successful verification.
    } else if (!deviceIsCurrentlyTrusted) {
      this.logger.debug(`[Login] Device ${device.id} (user ${user.id}) is NOT trusted. Proceeding with verifications.`)
    }
    // It's also possible 'deviceIsCurrentlyTrusted' is true, but 'forceReverificationDueToRevoke' is true.
    // The above logs cover the main branches.

    // Now, determine the type of verification needed, prioritizing 2FA if enabled.
    const needsAdminReverification = await this.tokenService.checkDeviceNeedsReverification(user.id, device.id)
    if (needsAdminReverification) {
      this.logger.debug(
        `[Login] Device ${device.id} (user ${user.id}) is also marked for admin-initiated reverification.`
      )
    }

    if (user.twoFactorEnabled) {
      this.logger.debug(`[Login] User ${user.id} has 2FA enabled. Initiating 2FA verification for device ${device.id}.`)
      return this.initiate2FAVerification(user, device, rememberMe, res)
    } else {
      this.logger.debug(
        `[Login] User ${user.id} does not have 2FA enabled. Initiating device OTP verification for device ${device.id}.`
      )
      return this.initiateDeviceVerification(user, device, rememberMe, res)
    }
  }

  /**
   * Làm mới token
   */
  async refreshToken(refreshToken: string, deviceInfo: any, res: Response): Promise<{ accessToken: string }> {
    try {
      const { userAgent, ip } = deviceInfo

      // Xác minh refresh token
      const payload = await this.tokenService.verifyRefreshToken(refreshToken)

      // Kiểm tra token có trong blacklist không
      const isBlacklisted = await this.tokenService.isRefreshTokenJtiBlacklisted(payload.jti)
      if (isBlacklisted) {
        throw AuthError.InvalidRefreshToken()
      }

      // Đánh dấu refresh token cũ là đã sử dụng
      await this.tokenService.markRefreshTokenJtiAsUsed(payload.jti, payload.sessionId)

      // Tạo payload mới
      const newPayload = {
        userId: payload.userId,
        deviceId: payload.deviceId,
        roleId: payload.roleId,
        roleName: payload.roleName,
        sessionId: payload.sessionId,
        jti: `access_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`,
        isDeviceTrustedInSession: payload.isDeviceTrustedInSession
      }

      // Tạo token mới
      const newAccessToken = this.tokenService.signAccessToken(newPayload)
      const newRefreshToken = this.tokenService.signRefreshToken({
        ...newPayload,
        jti: `refresh_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`
      })

      // Set cookie mới
      this.cookieService.setTokenCookies(res, newAccessToken, newRefreshToken)

      return {
        accessToken: newAccessToken
      }
    } catch (error) {
      this.logger.error(`Lỗi làm mới token: ${error.message}`, error.stack)
      this.cookieService.clearTokenCookies(res)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  /**
   * Đăng xuất
   */
  async logout(userId: number, sessionId: string, req?: Request, res?: Response): Promise<void> {
    try {
      // Xóa cookie nếu có response
      if (res) {
        // Xóa các cookie liên quan đến đăng nhập
        this.cookieService.clearTokenCookies(res)

        // Xóa SLT cookie nếu có
        this.cookieService.clearSltCookie(res)

        // Xóa các cookie khác nếu có (trừ csrf)
        const cookies = req?.cookies
        if (cookies) {
          Object.keys(cookies).forEach((cookieName) => {
            if (cookieName !== '_csrf' && cookieName !== 'xsrf-token') {
              res.clearCookie(cookieName, { path: '/' })
              this.logger.debug(`[logout] Cookie ${cookieName} đã được xóa`)
            }
          })
        }
      }

      // Đánh dấu session là đã vô hiệu hóa
      await this.tokenService.invalidateSession(sessionId, 'USER_LOGOUT')

      // Đánh dấu token là đã vô hiệu hóa nếu có request
      if (req) {
        const accessToken = this.tokenService.extractTokenFromRequest(req)
        if (accessToken) {
          try {
            const payload = await this.tokenService.verifyAccessToken(accessToken)
            await this.tokenService.invalidateAccessTokenJti(payload.jti, payload.exp)
          } catch (error) {
            this.logger.warn(`Lỗi vô hiệu hóa access token khi logout: ${error.message}`)
          }
        }
      }
    } catch (error) {
      this.logger.error(`Lỗi đăng xuất: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  /**
   * Tìm người dùng theo email
   */
  async findUserByEmail(email: string): Promise<any> {
    return this.userAuthRepository.findByEmailOrUsername(email)
  }

  /**
   * Bắt đầu quá trình xác thực thiết bị thông qua OTP
   */
  private async initiateDeviceVerification(
    user: User & { role: Role; userProfile: UserProfile | null },
    device: Device,
    rememberMe: boolean,
    res: Response
  ): Promise<any> {
    try {
      // Gửi OTP qua email và khởi tạo SLT cookie
      const sltToken = await this.otpService.initiateOtpWithSltCookie({
        email: user.email,
        userId: user.id,
        deviceId: device.id,
        ipAddress: device.ip,
        userAgent: device.userAgent,
        purpose: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
        metadata: {
          deviceId: device.id,
          rememberMe: rememberMe
        }
      })

      // Đặt cookie SLT
      this.cookieService.setSltCookie(res, sltToken, TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP)

      this.logger.debug(`[login] Device verification required, SLT cookie set for ${user.email}`)

      // Phản hồi về client
      return {
        message: this.i18nService.t('Auth.Auth.Login.DeviceVerificationRequired' as I18nPath, {
          lang: I18nContext.current()?.lang
        }),
        requiresDeviceVerification: true,
        verificationType: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
        verificationRedirectUrl: '/auth/otp/verify',
        email: user.email
      }
    } catch (error) {
      this.logger.error(`[initiateDeviceVerification] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  /**
   * Bắt đầu quá trình xác thực hai yếu tố
   */
  private async initiate2FAVerification(
    user: User & { role: Role; userProfile: UserProfile | null },
    device: Device,
    rememberMe: boolean,
    res: Response
  ): Promise<any> {
    try {
      // Tạo và đặt SLT token cho xác thực 2FA
      const sltToken = await this.otpService.initiateOtpWithSltCookie({
        email: user.email,
        userId: user.id,
        deviceId: device.id,
        ipAddress: device.ip,
        userAgent: device.userAgent,
        purpose: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_2FA,
        metadata: {
          deviceId: device.id,
          rememberMe: rememberMe,
          twoFactorMethod: user.twoFactorMethod
        }
      })

      // Đặt cookie SLT
      this.cookieService.setSltCookie(res, sltToken, TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_2FA)

      // Phản hồi về client
      return {
        message: this.i18nService.t('Auth.Auth.Login.2FARequired' as I18nPath, { lang: I18nContext.current()?.lang }),
        requires2FA: true,
        twoFactorMethod: user.twoFactorMethod,
        verificationRedirectUrl: '/auth/2fa/verify',
        email: user.email
      }
    } catch (error) {
      this.logger.error(`[initiate2FAVerification] Error: ${error.message}`, error.stack)
      if (error instanceof HttpException) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  /**
   * Lấy thiết bị dựa trên ID
   */
  async getDeviceById(deviceId: number): Promise<Device | null> {
    if (!deviceId) return null

    try {
      return this.deviceRepository.findById(deviceId)
    } catch (error) {
      this.logger.error(`[getDeviceById] Error: ${error.message}`, error.stack)
      return null
    }
  }

  /**
   * Hoàn tất đăng nhập khi không cần xác thực bổ sung
   */
  async finalizeLoginAndCreateTokens(
    user: User & { role: Role; userProfile: UserProfile | null },
    device: Device,
    rememberMe: boolean,
    res: Response,
    ipAddress?: string,
    userAgent?: string,
    isTrustedSession?: boolean // Tham số mới để xác định rõ trạng thái tin cậy
  ): Promise<any> {
    try {
      const effectiveIsTrustedSession =
        isTrustedSession === undefined ? await this.deviceRepository.isDeviceTrustValid(device.id) : isTrustedSession

      // Tạo thông tin người dùng để phản hồi
      const userResponse = {
        id: user.id,
        email: user.email,
        role: user.role.name,
        isDeviceTrustedInSession: effectiveIsTrustedSession, // Sử dụng trạng thái tin cậy đã xác định
        userProfile: user.userProfile
      }

      // Tạo session ID duy nhất
      const sessionId = uuidv4()

      // Tạo token
      const payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'> = {
        userId: user.id,
        roleId: user.role.id,
        roleName: user.role.name,
        deviceId: device.id,
        sessionId,
        jti: `access_${Date.now()}_${this.generateRandomId()}`,
        isDeviceTrustedInSession: effectiveIsTrustedSession // Đặt cờ này chính xác
      }

      const accessToken = this.tokenService.signAccessToken(payload)
      const refreshToken = this.tokenService.signRefreshToken({
        ...payload,
        jti: `refresh_${Date.now()}_${this.generateRandomId()}`
      })

      // Đặt cookie token
      const refreshCookieMaxAge = rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000
      this.cookieService.setTokenCookies(res, accessToken, refreshToken, refreshCookieMaxAge)

      // Tạo phiên trong Redis
      // Tính thời gian hết hạn cho phiên
      const refreshTokenExpiryDays = rememberMe ? 30 : 1
      const expiresAt = new Date()
      expiresAt.setDate(expiresAt.getDate() + refreshTokenExpiryDays)

      await this.sessionRepository.createSession({
        id: sessionId,
        userId: user.id,
        deviceId: device.id,
        ipAddress: ipAddress || 'Unknown',
        userAgent: userAgent || 'Unknown',
        expiresAt
      })

      return {
        accessToken,
        refreshToken,
        user: userResponse,
        message: this.i18nService.t('Auth.Auth.Login.Success' as I18nPath, { lang: I18nContext.current()?.lang })
      }
    } catch (error) {
      this.logger.error(`[finalizeLoginAndCreateTokens] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }

  /**
   * Helper để tạo ID ngẫu nhiên
   */
  private generateRandomId(length: number = 12): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    let result = ''
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length))
    }
    return result
  }

  /**
   * Hoàn tất đăng nhập sau khi xác minh
   */
  async finalizeLoginAfterVerification(
    userId: number,
    deviceId: number,
    rememberMe: boolean,
    res: Response,
    ipAddress?: string,
    userAgent?: string
  ): Promise<any> {
    try {
      // Tìm user
      const user = await this.userAuthRepository.findById(userId)
      if (!user) {
        throw AuthError.EmailNotFound()
      }

      // Tìm thiết bị
      const device = await this.deviceRepository.findById(deviceId)
      if (!device) {
        throw AuthError.DeviceNotFound()
      }

      // Sau khi xác minh thành công và nếu rememberMe là true, thiết bị NÊN được trust.
      // Trạng thái isTrusted của device có thể chưa được cập nhật ngay lập tức trong đối tượng device này
      // nếu việc trust device xảy ra trong một tiến trình khác hoặc ngay trước khi gọi hàm này.
      // Do đó, nếu rememberMe là true, ta có thể coi isDeviceTrustedInSession là true cho token mới.
      const isDeviceTrustedNow = rememberMe || (await this.deviceRepository.isDeviceTrustValid(deviceId))

      // Tạo thông tin người dùng để phản hồi
      const userResponse = {
        id: user.id,
        email: user.email,
        role: user.role.name,
        isDeviceTrustedInSession: isDeviceTrustedNow,
        userProfile: user.userProfile
      }

      // Tạo session ID duy nhất
      const sessionId = uuidv4()

      // Tạo token
      const payload = {
        userId: user.id,
        roleId: user.role.id,
        roleName: user.role.name,
        deviceId: device.id,
        sessionId,
        jti: `access_${Date.now()}_${this.generateRandomId()}`,
        isDeviceTrustedInSession: isDeviceTrustedNow // Đặt cờ này chính xác
      }

      const accessToken = this.tokenService.signAccessToken(payload)
      const refreshToken = this.tokenService.signRefreshToken({
        ...payload,
        jti: `refresh_${Date.now()}_${this.generateRandomId()}`
      })

      // Đặt cookie token
      const refreshCookieMaxAge = rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000
      this.cookieService.setTokenCookies(res, accessToken, refreshToken, refreshCookieMaxAge)

      // Tạo phiên trong Redis
      // Tính thời gian hết hạn cho phiên
      const refreshTokenExpiryDays = rememberMe ? 30 : 1
      const expiresAt = new Date()
      expiresAt.setDate(expiresAt.getDate() + refreshTokenExpiryDays)

      await this.sessionRepository.createSession({
        id: sessionId,
        userId: user.id,
        deviceId: device.id,
        ipAddress: ipAddress || 'Unknown',
        userAgent: userAgent || 'Unknown',
        expiresAt
      })

      this.logger.debug(`[finalizeLoginAfterVerification] Session ${sessionId} created in Redis for user ${userId}`)

      return {
        accessToken,
        refreshToken,
        user: userResponse,
        message: this.i18nService.t('Auth.Auth.Login.Success' as I18nPath, { lang: I18nContext.current()?.lang })
      }
    } catch (error) {
      this.logger.error(`[finalizeLoginAfterVerification] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }
}
