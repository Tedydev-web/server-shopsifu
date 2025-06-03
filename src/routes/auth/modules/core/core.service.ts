import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { v4 as uuidv4 } from 'uuid'
import { Response, Request } from 'express'
import { AuthError } from '../../auth.error'
import { CookieService } from '../../shared/cookie/cookie.service'
import { TokenService } from '../../shared/token/token.service'
import { HashingService } from 'src/shared/services/hashing.service'
import { UserAuthRepository } from '../../repositories/user-auth.repository'
import { DeviceRepository } from '../../repositories/device.repository'
import { SessionRepository } from '../../repositories/session.repository'
import { IUserAuthService } from 'src/shared/types/auth.types'
import { TwoFactorMethodType, TypeOfVerificationCode } from '../../constants/auth.constants'
import { OtpService } from '../../modules/otp/otp.service'

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
    private readonly cookieService: CookieService,
    private readonly tokenService: TokenService,
    private readonly i18nService: I18nService,
    private readonly configService: ConfigService,
    private readonly userAuthRepository: UserAuthRepository,
    private readonly deviceRepository: DeviceRepository,
    private readonly otpService: OtpService,
    private readonly sessionRepository: SessionRepository
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

    this.logger.log(`Đăng ký thành công cho user với email ${email}`)
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
    const { emailOrUsername, password, rememberMe = false, ip, userAgent } = params

    this.logger.debug(`[login] Trying to login user with email/username: ${emailOrUsername}`)

    // Kiểm tra user có tồn tại không
    const user = await this.validateUser(emailOrUsername, password)

    // Tìm hoặc tạo thiết bị
    const existingDevices = await this.deviceRepository.findDevicesByUserId(user.id)
    const isFirstTimeLogin = existingDevices.length === 0
    this.logger.debug(
      `[login] User ${emailOrUsername}: found ${existingDevices.length} devices, isFirstTimeLogin=${isFirstTimeLogin}`
    )

    // Tạo hoặc cập nhật thiết bị
    const device = await this.deviceRepository.upsertDevice(user.id, userAgent || 'Unknown', ip || 'Unknown')
    this.logger.debug(`[login] User ${emailOrUsername}: Device ID=${device.id}, isTrusted=${device.isTrusted}`)

    // Check 2FA
    const twoFactorEnabled = user.twoFactorEnabled === true
    this.logger.debug(`[login] User ${emailOrUsername}: 2FA enabled=${twoFactorEnabled}`)

    // Kiểm tra thiết bị có được tin tưởng hay không
    const isDeviceTrusted = device.isTrusted && (await this.deviceRepository.isDeviceTrustValid(device.id))
    this.logger.debug(`[login] Final device trust status: ${isDeviceTrusted}`)

    // Nếu 2FA được bật hoặc thiết bị chưa được tin cậy, yêu cầu xác thực thêm
    const requiresAdditionalVerification = (twoFactorEnabled && !isDeviceTrusted) || !isDeviceTrusted
    this.logger.debug(
      `[login] Additional verification needed: 2FA=${twoFactorEnabled}, untrusted device=${!isDeviceTrusted}, bypass 2FA=${twoFactorEnabled && isDeviceTrusted}`
    )

    if (requiresAdditionalVerification) {
      // Nếu 2FA được bật, yêu cầu xác thực 2FA
      if (twoFactorEnabled) {
        this.logger.debug(`[login] Initiating 2FA verification for user ${emailOrUsername}`)

        // Tạo JWT token để lưu thông tin phiên đăng nhập
        const sltJwtPayload = {
          jti: `slt_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`,
          sub: user.id,
          pur: TypeOfVerificationCode.LOGIN_2FA
        }

        const sltJwt = this.tokenService.signShortLivedToken(sltJwtPayload)

        // Lưu context vào Redis
        const contextKey = `slt:context:${sltJwtPayload.jti}`
        const contextData = {
          userId: String(user.id),
          deviceId: String(device.id),
          ipAddress: ip || 'Unknown',
          userAgent: userAgent || 'Unknown',
          purpose: TypeOfVerificationCode.LOGIN_2FA,
          sltJwtExp: String(Math.floor(Date.now() / 1000) + 300), // 5 phút
          sltJwtCreatedAt: String(Date.now()),
          finalized: '0',
          attempts: '0',
          metadata: JSON.stringify({
            deviceId: device.id,
            rememberMe,
            twoFactorMethod: user.twoFactorMethod || TwoFactorMethodType.TOTP,
            requiresDeviceVerification: !isDeviceTrusted
          }),
          email: user.email
        }

        await this.otpService['redisService'].hset(contextKey, contextData as any)
        await this.otpService['redisService'].expire(contextKey, 360) // 6 phút

        // Set SLT cookie
        this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.LOGIN_2FA)
        this.logger.debug(`[login] 2FA verification required, SLT cookie set for ${emailOrUsername}`)

        // Return message asking for 2FA code
        return {
          message: await this.i18nService.translate('Auth.Login.2FARequired'),
          requiresDeviceVerification: true,
          verificationType: '2FA',
          verificationRedirectUrl: '/auth/2fa/verify'
        }
      }

      // Nếu thiết bị chưa được tin cậy, yêu cầu xác thực thiết bị qua OTP
      if (!isDeviceTrusted) {
        this.logger.debug(`[login] Initiating device verification for user ${emailOrUsername}`)

        // Gửi OTP và tạo SLT cookie
        const sltJwt = await this.otpService.initiateOtpWithSltCookie({
          email: user.email,
          userId: user.id,
          deviceId: device.id,
          ipAddress: ip || 'Unknown',
          userAgent: userAgent || 'Unknown',
          purpose: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
          metadata: { deviceId: device.id, rememberMe }
        })

        // Set SLT cookie
        this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP)
        this.logger.debug(`[login] Device verification required, SLT cookie set for ${emailOrUsername}`)

        // Return message asking for device verification
        return {
          message: await this.i18nService.translate('Auth.Login.DeviceVerificationOtpRequired'),
          requiresDeviceVerification: true,
          verificationType: 'OTP',
          verificationRedirectUrl: '/auth/otp/verify'
        }
      }
    }

    // Nếu không cần xác thực thêm, hoàn tất đăng nhập
    return await this.finalizeLoginAfterVerification(user.id, device.id, rememberMe || false, res, ip, userAgent)
  }

  /**
   * Làm mới token
   */
  async refreshToken(refreshToken: string, deviceInfo: any, res: Response): Promise<any> {
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
      this.logger.error(`Lỗi làm mới token: ${error.message}`)
      this.cookieService.clearTokenCookies(res)
      throw error
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
            this.logger.error(`Lỗi vô hiệu hóa token: ${error.message}`)
          }
        }
      }
    } catch (error) {
      this.logger.error(`Lỗi đăng xuất: ${error.message}`)
      throw error
    }
  }

  /**
   * Tìm người dùng theo email
   */
  async findUserByEmail(email: string): Promise<any> {
    return this.userAuthRepository.findByEmailOrUsername(email)
  }

  /**
   * Hoàn tất đăng nhập sau khi xác minh OTP
   */
  async finalizeLoginAfterVerification(
    userId: number,
    deviceId: number,
    rememberMe: boolean,
    res: Response,
    ipAddress?: string,
    userAgent?: string
  ): Promise<any> {
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

    // Không tự động đánh dấu thiết bị là trusted, để người dùng xác nhận sau
    // (Dòng code này đã bị xóa: await this.deviceRepository.updateDeviceTrustStatus(deviceId, true))

    // Tạo session ID
    const sessionId = uuidv4()

    // Tạo payload cho access token
    const tokenPayload = {
      userId: user.id,
      deviceId: device.id,
      roleId: user.roleId,
      roleName: user.role.name,
      sessionId,
      jti: `access_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`,
      isDeviceTrustedInSession: false // Thiết bị chưa được tin cậy
    }

    // Tạo tokens
    const accessToken = this.tokenService.signAccessToken(tokenPayload)
    const refreshToken = this.tokenService.signRefreshToken({
      ...tokenPayload,
      jti: `refresh_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`
    })

    // Set cookie
    this.cookieService.setTokenCookies(
      res,
      accessToken,
      refreshToken,
      rememberMe ? 30 * 24 * 60 * 60 * 1000 : undefined
    )

    // Tạo session trong Redis
    const sessionExpiresInMs = rememberMe
      ? this.configService.get<number>('SESSION_REMEMBER_ME_DURATION_MS')
      : this.configService.get<number>('SESSION_DEFAULT_DURATION_MS')

    const expiresAt = new Date(Date.now() + (sessionExpiresInMs || 0))

    try {
      await this.sessionRepository.createSession({
        id: sessionId,
        userId,
        deviceId,
        ipAddress: ipAddress || 'Unknown',
        userAgent: userAgent || 'Unknown',
        expiresAt
      })
      this.logger.debug(`[finalizeLoginAfterVerification] Session ${sessionId} created in Redis for user ${userId}`)
    } catch (error) {
      this.logger.error(
        `[finalizeLoginAfterVerification] Failed to create session ${sessionId} in Redis for user ${userId}: ${error.message}`,
        error.stack
      )
      // Quyết định có nên throw lỗi ở đây hay không, hoặc chỉ log
      // Hiện tại, chỉ log để không làm gián đoạn quá trình đăng nhập
    }

    // Trả về thông tin user với cấu trúc giống login
    return {
      id: user.id,
      email: user.email,
      roleName: user.role.name, // Sử dụng roleName để phù hợp với otp.controller
      isDeviceTrustedInSession: false,
      userProfile: {
        firstName: user.userProfile?.firstName,
        lastName: user.userProfile?.lastName,
        username: user.userProfile?.username,
        avatar: user.userProfile?.avatar
      }
    }
  }
}
