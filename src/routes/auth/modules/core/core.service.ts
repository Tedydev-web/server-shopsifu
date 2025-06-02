import { Injectable, Logger } from '@nestjs/common'
import { Response, Request } from 'express'
import { HashingService } from 'src/shared/services/hashing.service'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { CookieService } from 'src/routes/auth/shared/cookie/cookie.service'
import { TokenService } from 'src/routes/auth/shared/token/token.service'
import { I18nService } from 'nestjs-i18n'
import { ConfigService } from '@nestjs/config'
import { AuthError } from 'src/routes/auth/auth.error'
import { v4 as uuidv4 } from 'uuid'
import { UserAuthRepository } from '../../repositories/user-auth.repository'
import { DeviceRepository } from '../../repositories/device.repository'
import { IUserAuthService } from 'src/shared/types/auth.types'

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
    private readonly deviceRepository: DeviceRepository
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

    // Validate user
    const user = await this.validateUser(emailOrUsername, password)

    if (!user) {
      throw AuthError.InvalidPassword()
    }

    // Tạo hoặc tìm device
    const device = await this.deviceRepository.upsertDevice(user.id, userAgent || 'unknown', ip || 'unknown')

    // Kiểm tra 2FA (to be implemented)
    const requiresTwoFactorAuth = !!user.twoFactorEnabled && !!user.twoFactorSecret

    // Kiểm tra thiết bị đã được tin tưởng chưa
    const isDeviceTrusted = !!device.isTrusted

    // Nếu yêu cầu 2FA hoặc thiết bị chưa được tin tưởng, trả về SLT
    if (requiresTwoFactorAuth || !isDeviceTrusted) {
      // To be implemented with OtpService
      return {
        message: await this.i18nService.translate('Auth.Login.2FARequired'),
        requiresTwoFactorAuth,
        requiresDeviceVerification: !isDeviceTrusted
      }
    }

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
}
