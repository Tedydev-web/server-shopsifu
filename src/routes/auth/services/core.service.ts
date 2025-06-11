import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { v4 as uuidv4 } from 'uuid'
import { Response, Request } from 'express'
import { AuthError } from '../auth.error'
import { HashingService } from 'src/shared/services/hashing.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { GlobalError } from 'src/shared/global.error'
import {
  ICookieService,
  ITokenService,
  ILoginFinalizerService,
  ILoginFinalizationPayload,
  ISLTService
} from 'src/routes/auth/auth.types'
import { TypeOfVerificationCode } from 'src/routes/auth/auth.constants'
import { OtpService } from './otp.service'
import { User, Device, Role, UserProfile } from '@prisma/client'
import { AccessTokenPayloadCreate } from 'src/routes/auth/auth.types'
import {
  COOKIE_SERVICE,
  DEVICE_SERVICE,
  HASHING_SERVICE,
  SLT_SERVICE,
  TOKEN_SERVICE,
  EMAIL_SERVICE
} from 'src/shared/constants/injection.tokens'
import { SessionRepository } from 'src/routes/auth/repositories'
import { RedisService } from 'src/shared/services/redis.service'
import { DeviceService } from './device.service'
import { SessionsService } from 'src/routes/auth/services/session.service'
import { AuthVerificationService } from './auth-verification.service'
import { CompleteRegistrationDto, LoginDto } from '../dtos/core.dto'
import { ConfigService } from '@nestjs/config'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { EmailService } from 'src/shared/services/email.service'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { DeviceRepository } from 'src/shared/repositories/device.repository'
import { UserRepository, UserWithProfileAndRole } from 'src/routes/user/user.repository'
import { ProfileRepository } from 'src/routes/profile/profile.repository'
import { RoleRepository } from 'src/routes/role/role.repository'

interface RegisterUserParams {
  userId: number
  password?: string
  confirmPassword?: string
  firstName?: string
  lastName?: string
  username?: string
  phoneNumber?: string
  ip?: string
  userAgent?: string
}

@Injectable()
export class CoreService implements ILoginFinalizerService {
  private readonly logger = new Logger(CoreService.name)

  constructor(
    private readonly configService: ConfigService,
    private readonly i18nService: I18nService<I18nTranslations>,
    private readonly userRepository: UserRepository,
    private readonly profileRepository: ProfileRepository,
    private readonly roleRepository: RoleRepository,
    private readonly deviceRepository: DeviceRepository,
    private readonly otpService: OtpService,
    private readonly sessionRepository: SessionRepository,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly redisService: RedisService,
    @Inject(SLT_SERVICE) private readonly sltService: ISLTService,
    @Inject(DEVICE_SERVICE) private readonly deviceService?: DeviceService,
    @Inject(forwardRef(() => SessionsService)) private readonly sessionsService?: SessionsService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService?: AuthVerificationService,
    @Inject(EMAIL_SERVICE) private readonly emailService?: EmailService
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
    const exists = await this.profileRepository.doesUsernameExist(username)

    // Nếu username đã tồn tại, thêm số ngẫu nhiên
    if (exists) {
      const randomSuffix = Math.floor(Math.random() * 10000)
      username = `${username.substring(0, 10)}${randomSuffix}`
    }

    return username
  }

  /**
   * Khởi tạo đăng ký
   */
  async initiateRegistration(email: string, ipAddress: string, userAgent: string, res: Response): Promise<any> {
    try {
      // Kiểm tra email đã tồn tại chưa
      await this.checkEmailNotExists(email)

      if (!this.authVerificationService) {
        throw AuthError.ServiceNotAvailable('AuthVerificationService')
      }

      // Không tạo user tạm thời, chỉ khởi tạo quá trình xác thực với email và metadata
      const verificationResult = await this.authVerificationService.initiateVerification(
        {
          userId: 0, // Giá trị tạm thời sẽ được tạo bởi SLT service
          deviceId: 0, // Giá trị tạm thời sẽ được tạo bởi SLT service
          email: email,
          ipAddress: ipAddress,
          userAgent: userAgent,
          purpose: TypeOfVerificationCode.REGISTER,
          metadata: { pendingEmail: email, from: 'initiate-registration' }
        },
        res
      )

      return verificationResult
    } catch (error) {
      this.logger.error(`[initiateRegistration] Error: ${error.message}`, error.stack)
      if (error instanceof ApiException) throw error
      throw GlobalError.InternalServerError()
    }
  }

  /**
   * Hoàn tất đăng ký bằng SLT
   */
  async completeRegistrationWithSlt(
    sltCookie: string,
    params: CompleteRegistrationDto,
    ipAddress?: string,
    userAgent?: string
  ): Promise<any> {
    if (params.password !== params.confirmPassword) {
      throw AuthError.PasswordsNotMatch()
    }

    if (!this.sltService) throw AuthError.ServiceNotAvailable('SLTService')

    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(
      sltCookie,
      ipAddress || 'unknown',
      userAgent || 'unknown',
      TypeOfVerificationCode.REGISTER
    )

    if (sltContext.metadata?.otpVerified !== 'true') {
      throw AuthError.InsufficientPermissions()
    }

    // Lấy email từ metadata hoặc trực tiếp từ context
    const email = sltContext.metadata?.pendingEmail || sltContext.email
    if (!email) {
      throw AuthError.EmailMissingInSltContext()
    }

    // Kiểm tra email không tồn tại trong cơ sở dữ liệu
    await this.checkEmailNotExists(email)

    // Hoàn tất đăng ký với thông tin từ params
    const newUser = await this.createUserAndProfile({
      email,
      password: params.password,
      firstName: params.firstName,
      lastName: params.lastName,
      username: params.username,
      phoneNumber: params.phoneNumber,
      ip: ipAddress,
      userAgent: userAgent
    })

    // Gửi email chào mừng
    if (this.emailService) {
      await this.emailService.sendWelcomeEmail(email, {
        userName: newUser.userProfile?.username || email.split('@')[0]
      })
    }

    // Finalize SLT
    await this.sltService.finalizeSlt(sltContext.sltJti)
    this.logger.log(`[completeRegistrationWithSlt] Registration completed and SLT finalized for email: ${email}`)

    return {
      message: this.i18nService.t('auth.success.register.complete')
    }
  }

  /**
   * Tạo người dùng và hồ sơ trong cơ sở dữ liệu.
   * Được gọi sau khi tất cả các bước xác minh đã hoàn tất.
   */
  async createUserAndProfile(
    params: Omit<RegisterUserParams, 'userId'> & { email: string }
  ): Promise<UserWithProfileAndRole> {
    const { email, password, firstName, lastName, username: providedUsername, phoneNumber } = params

    // 1. Kiểm tra email đã tồn tại chưa
    await this.checkEmailNotExists(email)

    // 2. Xử lý Username
    let finalUsername: string
    if (providedUsername) {
      const usernameExists = await this.profileRepository.doesUsernameExist(providedUsername)
      if (usernameExists) {
        throw AuthError.UsernameAlreadyExists(providedUsername)
      }
      finalUsername = providedUsername
    } else {
      finalUsername = await this.generateUniqueUsername(email.split('@')[0])
    }

    // 3. Hash mật khẩu
    const hashedPassword = password ? await this.hashingService.hash(password) : undefined
    if (!hashedPassword) {
      this.logger.error('Password is required for new user creation but was not provided or hashing failed.')
      throw GlobalError.InternalServerError(this.i18nService.t('auth.error.passwordProcessingFailed'))
    }

    // 4. Lấy Role ID cho 'Customer'
    const customerRole = await this.roleRepository.findByName('Customer')
    if (!customerRole) {
      this.logger.error('Default "Customer" role not found in the database.')
      // TODO: Consider creating the 'Customer' role if it doesn't exist, or having a more robust fallback/setup mechanism.
      throw GlobalError.InternalServerError(this.i18nService.t('auth.error.roleConfigurationError'))
    }

    // 5. Gọi repository để tạo user
    return this.userRepository.createWithProfile({
      email,
      password: hashedPassword,
      roleId: customerRole.id,
      username: finalUsername,
      firstName,
      lastName,
      phoneNumber
      // googleId and googleAvatar are not part of RegisterUserParams,
      // they are part of CreateUserData directly for social logins if needed.
      // If they are needed here, RegisterUserParams should be updated.
    })
  }

  /**
   * Validate user credentials
   */
  async validateUser(
    emailOrUsername: string,
    password: string
  ): Promise<Omit<UserWithProfileAndRole, 'password' | 'role.permissions'> | null> {
    // Tìm user theo email hoặc username
    const user = await this.userRepository.findByEmailOrUsername(emailOrUsername)

    // Kiểm tra user tồn tại
    if (!user || !user.password) {
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

  async getOrCreateDevice(userId: number, ip?: string, userAgent?: string): Promise<Device> {
    try {
      const device = await this.deviceRepository.upsertDevice(
        userId,
        userAgent || 'Unknown',
        ip || 'Unknown',
        `Device from ${userAgent?.substring(0, 20) || 'Unknown UA'} at ${new Date().toLocaleDateString()}`
      )
      return device
    } catch (error) {
      this.logger.error(`[Login] Error upserting device for user ${userId}: ${error.message}`, error.stack)
      throw AuthError.DeviceProcessingFailed()
    }
  }

  /**
   * Làm mới token
   */
  async refreshToken(req: Request, deviceInfo: { ipAddress: string; userAgent: string }, res: Response): Promise<any> {
    try {
      const refreshToken = this.tokenService.extractRefreshTokenFromRequest(req)
      if (!refreshToken) {
        throw AuthError.MissingRefreshToken()
      }

      // Xác minh refresh token
      const payload = await this.tokenService.verifyRefreshToken(refreshToken)

      // Kiểm tra token có trong blacklist không
      const isBlacklisted = await this.tokenService.isRefreshTokenJtiBlacklisted(payload.jti)
      if (isBlacklisted) {
        throw AuthError.InvalidRefreshToken()
      }

      // Lấy thông tin user mới nhất
      const user = await this.userRepository.findByIdWithDetails(payload.userId)
      if (!user) {
        throw GlobalError.NotFound('user')
      }

      // Đánh dấu refresh token cũ là đã sử dụng
      await this.tokenService.markRefreshTokenJtiAsUsed(payload.jti, payload.sessionId)

      // Tạo payload mới với thông tin đầy đủ
      const newPayload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'> = {
        userId: user.id,
        email: user.email,
        roleId: user.role.id,
        roleName: user.role.name,
        deviceId: payload.deviceId,
        sessionId: payload.sessionId,
        jti: `access_${Date.now()}_${this.generateRandomId()}`,
        isDeviceTrustedInSession: payload.isDeviceTrustedInSession
      }

      // Tạo token mới
      const newAccessToken = this.tokenService.signAccessToken(newPayload)
      const newRefreshToken = this.tokenService.signRefreshToken({
        ...newPayload,
        jti: `refresh_${Date.now()}_${this.generateRandomId()}`
      })

      // Set cookie mới
      this.cookieService.setTokenCookies(res, newAccessToken, newRefreshToken)

      return { message: this.i18nService.t('auth.success.token.refreshed') }
    } catch (error) {
      this.logger.error(`Error refreshing token: ${error.message}`, error.stack)
      this.cookieService.clearTokenCookies(res)
      if (error instanceof ApiException) throw error
      throw GlobalError.InternalServerError()
    }
  }

  /**
   * Đăng xuất
   */
  async logout(userId: number, sessionId: string, req?: Request, res?: Response): Promise<{ message: string }> {
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
      if (this.sessionsService) {
        await this.sessionsService.invalidateSession(sessionId, 'logout')
      } else {
        // Log warning khi không có SessionsService
        this.logger.warn(`[logout] SessionsService không khả dụng, không thể vô hiệu hóa session ${sessionId}`)
      }

      // Đánh dấu token là đã vô hiệu hóa nếu có request
      if (req) {
        const accessToken = this.tokenService.extractTokenFromRequest(req)
        if (accessToken) {
          try {
            const payload = await this.tokenService.verifyAccessToken(accessToken)
            await this.tokenService.invalidateAccessTokenJti(payload.jti, payload.exp)
          } catch (error) {
            this.logger.warn(`Error invalidating access token on logout: ${error.message}`)
          }
        }
      }

      return { message: this.i18nService.t('auth.success.logout.success') }
    } catch (error) {
      this.logger.error(`Logout error: ${error.message}`, error.stack)
      if (error instanceof ApiException) throw error
      throw GlobalError.InternalServerError()
    }
  }

  /**
   * Tìm người dùng theo email
   */
  async findUserByEmail(email: string): Promise<any> {
    return this.userRepository.findByEmailOrUsername(email)
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
    user: Omit<User & { role: Role; userProfile: UserProfile | null }, 'password'>,
    device: Device,
    rememberMe: boolean,
    res: Response,
    ipAddress?: string,
    userAgent?: string,
    isTrustedSession?: boolean
  ): Promise<any> {
    try {
      const sessionId = await this.createSessionForLogin(user.id, device.id, ipAddress, userAgent)
      const effectiveIsTrustedSession = isTrustedSession ?? (await this.deviceRepository.isDeviceTrustValid(device.id))

      this.generateAndSetAuthTokens(user, device.id, sessionId, effectiveIsTrustedSession, rememberMe, res)

      const userResponse = {
        id: user.id,
        roleId: user.role.id,
        roleName: user.role.name,
        email: user.email,
        username: user.userProfile?.username,
        avatar: user.userProfile?.avatar,
        isDeviceTrustedInSession: effectiveIsTrustedSession
      }

      return {
        message: this.i18nService.t('auth.success.login.success'),
        data: userResponse
      }
    } catch (error) {
      this.logger.error(`[finalizeLoginAndCreateTokens] Error: ${error.message}`, error.stack)
      if (error instanceof ApiException) throw error
      throw GlobalError.InternalServerError()
    }
  }

  /**
   * Tạo một session mới cho người dùng khi đăng nhập.
   */
  private async createSessionForLogin(
    userId: number,
    deviceId: number,
    ipAddress?: string,
    userAgent?: string
  ): Promise<string> {
    const now = new Date()
    const absoluteSessionLifetimeInSeconds =
      this.configService.get<number>('ABSOLUTE_SESSION_LIFETIME_MS', 30 * 24 * 60 * 60 * 1000) / 1000
    const expiresAtDate = new Date(now.getTime() + absoluteSessionLifetimeInSeconds * 1000)
    const sessionId = uuidv4()

    await this.sessionRepository.createSession({
      id: sessionId,
      userId: userId,
      deviceId: deviceId,
      createdAt: now.getTime(),
      expiresAt: expiresAtDate.getTime(),
      ipAddress: ipAddress ?? 'Unknown',
      userAgent: userAgent ?? 'Unknown'
    })

    this.logger.log(`[createSessionForLogin] Session ${sessionId} created for user ${userId}`)
    return sessionId
  }

  /**
   * Tạo và thiết lập access/refresh tokens cho người dùng.
   */
  private generateAndSetAuthTokens(
    user: Omit<UserWithProfileAndRole, 'password'>,
    deviceId: number,
    sessionId: string,
    isTrustedSession: boolean,
    rememberMe: boolean,
    res: Response
  ): { accessToken: string; refreshToken: string } {
    const payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'> = {
      userId: user.id,
      email: user.email,
      roleId: user.role.id,
      roleName: user.role.name,
      deviceId: deviceId,
      sessionId,
      jti: `access_${Date.now()}_${this.generateRandomId()}`,
      isDeviceTrustedInSession: isTrustedSession
    }

    const accessToken = this.tokenService.signAccessToken(payload)
    const refreshToken = this.tokenService.signRefreshToken({
      ...payload,
      jti: `refresh_${Date.now()}_${this.generateRandomId()}`
    })

    this.cookieService.setTokenCookies(res, accessToken, refreshToken, rememberMe)

    return { accessToken, refreshToken }
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
   * Kiểm tra email chưa tồn tại
   */
  async checkEmailNotExists(email: string): Promise<void> {
    const existingUser = await this.userRepository.findByEmail(email)
    if (existingUser) {
      throw AuthError.EmailAlreadyExists()
    }
  }

  async initiateLogin(loginDto: LoginDto, ip: string, userAgent: string, res: Response) {
    this.logger.log(`[Login] Bắt đầu đăng nhập cho người dùng ${loginDto.emailOrUsername}`)

    const user = await this.validateUser(loginDto.emailOrUsername, loginDto.password)
    if (!user) {
      throw AuthError.InvalidPassword()
    }

    // Kiểm tra xem người dùng có bị gắn cờ yêu cầu xác minh lại không
    const reverifyKey = RedisKeyManager.getUserReverifyNextLoginKey(user.id)
    const needsReverification = await this.redisService.get(reverifyKey)

    const device = await this.getOrCreateDevice(user.id, ip, userAgent)

    if (needsReverification) {
      this.logger.log(`[Login] Người dùng ${user.id} bị gắn cờ xác minh lại. Buộc phải qua luồng xác thực.`)
      // Xóa cờ ngay sau khi đọc để nó chỉ có hiệu lực một lần
      await this.redisService.del(reverifyKey)
    }

    if (!this.authVerificationService) {
      throw AuthError.ServiceNotAvailable('AuthVerificationService')
    }

    const verificationResult = await this.authVerificationService.initiateVerification(
      {
        userId: user.id,
        deviceId: device.id,
        email: user.email,
        ipAddress: ip,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.LOGIN,
        rememberMe: loginDto.rememberMe,
        metadata: { from: 'login', forceVerification: !!needsReverification }
      },
      res
    )

    // The interceptor will wrap this into the standard response format.
    // The `data` part contains any information the client might need, like a verification token (SLT).
    return verificationResult
  }

  /**
   * Hoàn tất đăng nhập sau khi xác minh
   */
  async finalizeLoginAfterVerification(payload: ILoginFinalizationPayload, res: Response): Promise<any> {
    const { userId, deviceId, rememberMe, ipAddress, userAgent } = payload
    try {
      // Tìm user
      const user = await this.userRepository.findByIdWithDetails(userId)
      if (!user) {
        throw GlobalError.NotFound('user')
      }

      // Tìm thiết bị
      const device = await this.deviceRepository.findById(deviceId)
      if (!device) {
        throw AuthError.DeviceNotFound()
      }

      // Check if the device was trusted *before* this successful login.
      const wasDeviceTrusted = await this.deviceRepository.isDeviceTrustValid(deviceId)

      // Sau khi xác minh thành công và nếu rememberMe là true, thiết bị NÊN được trust.
      const isDeviceTrustedNow = rememberMe || wasDeviceTrusted

      this.logger.debug(
        `[finalizeLoginAfterVerification] Calling finalizeLoginAndCreateTokens for user ${userId}, device ${deviceId}`
      )

      const loginResult = await this.finalizeLoginAndCreateTokens(
        user,
        device,
        rememberMe,
        res,
        ipAddress,
        userAgent,
        isDeviceTrustedNow
      )

      // Nếu đăng nhập trên một thiết bị chưa được tin cậy trước đó, hãy gửi thông báo.
      if (!wasDeviceTrusted && this.deviceService) {
        this.logger.log(`[finalizeLoginAfterVerification] Device ${deviceId} was untrusted, sending notification.`)
        // Chạy bất đồng bộ để không chặn phản hồi của người dùng
        if (this.deviceService) {
          void this.deviceService.notifyLoginOnUntrustedDevice(user, deviceId, ipAddress, userAgent)
        }
      }

      return loginResult
    } catch (error) {
      this.logger.error(`[finalizeLoginAfterVerification] Error: ${error.message}`, error.stack)
      if (error instanceof ApiException) throw error
      throw GlobalError.InternalServerError()
    }
  }
}
