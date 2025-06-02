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
import { IUserAuthService } from 'src/shared/types/auth.types'
import { TypeOfVerificationCode } from '../../constants/auth.constants'
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
    private readonly otpService: OtpService
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

    // Xác minh thông tin người dùng
    const user = await this.validateUser(emailOrUsername, password)
    if (!user) {
      throw AuthError.InvalidPassword()
    }

    // Kiểm tra nếu user bị khóa hoặc không active
    if (user.status === 'BLOCKED') {
      this.logger.warn(`[login] Blocked user attempted login: ${user.email}`)
      throw AuthError.AccountLocked()
    } else if (user.status === 'INACTIVE') {
      this.logger.warn(`[login] Inactive user attempted login: ${user.email}`)
      throw AuthError.AccountNotActive()
    }

    this.logger.debug(
      `[login] User ${user.email}: found ${user.devices?.length || 0} devices, isFirstTimeLogin=${!user.devices || user.devices.length === 0}`
    )

    // Lấy thông tin thiết bị truy cập hoặc tạo mới
    const device = await this.deviceRepository.upsertDevice(user.id, userAgent || 'Unknown', ip || 'Unknown')
    this.logger.debug(`[login] User ${user.email}: Device ID=${device.id}, isTrusted=${device.isTrusted}`)

    // Kiểm tra 2FA
    const hasTwoFactorEnabled = user.twoFactorEnabled === true
    this.logger.debug(`[login] User ${user.email}: 2FA enabled=${hasTwoFactorEnabled}`)

    // Xác định tình trạng tin cậy của thiết bị, kiểm tra cả thời hạn tin cậy
    const isDeviceTrusted = await this.deviceRepository.isDeviceTrusted(device.id)
    this.logger.debug(`[login] Final device trust status: ${isDeviceTrusted}`)

    // Xác định nếu cần xác minh bổ sung
    // Thiết bị tin cậy bypass cả 2FA và xác minh thiết bị
    const requiresTwoFactorAuth = hasTwoFactorEnabled && !isDeviceTrusted
    const requiresDeviceVerification = !isDeviceTrusted && !hasTwoFactorEnabled
    this.logger.debug(
      `[login] Additional verification needed: 2FA=${requiresTwoFactorAuth}, untrusted device=${requiresDeviceVerification}`
    )

    // Ưu tiên xác minh 2FA nếu đã bật và thiết bị chưa tin cậy
    if (requiresTwoFactorAuth) {
      this.logger.debug(`[login] Initiating 2FA verification for user ${user.email}`)

      // Khởi tạo SLT token cho xác thực 2FA
      const sltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: user.email,
        userId: user.id,
        deviceId: device.id,
        ipAddress: ip || 'Unknown',
        userAgent: userAgent || 'Unknown',
        purpose: TypeOfVerificationCode.LOGIN_2FA,
        metadata: {
          deviceId: device.id,
          rememberMe: rememberMe,
          twoFactorMethod: user.twoFactorMethod,
          requiresDeviceVerification: false // Đã không cần xác minh thiết bị sau 2FA nữa
        }
      })

      // Đặt cookie SLT cho 2FA
      this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.LOGIN_2FA)
      this.logger.debug(`[login] 2FA verification required, SLT cookie set for ${user.email}`)

      return {
        message: this.i18nService.t('auth.Auth.Login.2FARequired')
      }
    }

    // Nếu không cần 2FA nhưng thiết bị không được tin cậy, và tài khoản chưa bật 2FA
    if (requiresDeviceVerification) {
      this.logger.debug(`[login] Initiating device verification OTP for ${user.email}`)

      // Khởi tạo OTP cho thiết bị mới
      const sltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: user.email,
        userId: user.id,
        deviceId: device.id,
        ipAddress: ip || 'Unknown',
        userAgent: userAgent || 'Unknown',
        purpose: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
        metadata: {
          deviceId: device.id,
          rememberMe: rememberMe // Thêm trường rememberMe vào metadata
        }
      })

      // Đặt cookie SLT
      this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP)
      this.logger.debug(`[login] OTP sent and SLT cookie set for ${user.email}`)

      // Trả về thông báo yêu cầu xác minh thiết bị
      return {
        message: this.i18nService.t('auth.Auth.Login.DeviceVerificationOtpRequired')
      }
    }

    // Nếu không cần thêm xác minh, hoàn tất đăng nhập
    const sessionId = uuidv4()

    // Tạo payload cho access token
    const tokenPayload = {
      userId: user.id,
      deviceId: device.id,
      roleId: user.roleId,
      roleName: user.role.name,
      sessionId,
      jti: `access_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`,
      isDeviceTrustedInSession: isDeviceTrusted
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

    // Trả về thông tin user
    return {
      id: user.id,
      email: user.email,
      role: user.role.name,
      isDeviceTrustedInSession: isDeviceTrusted,
      userProfile: {
        firstName: user.userProfile?.firstName,
        lastName: user.userProfile?.lastName,
        username: user.userProfile?.username,
        avatar: user.userProfile?.avatar
      }
    }
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
        this.cookieService.clearTokenCookies(res)
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
    res: Response
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

    // Trả về thông tin user
    return {
      id: user.id,
      email: user.email,
      roleName: user.role.name,
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
