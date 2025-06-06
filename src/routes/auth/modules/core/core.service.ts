import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { v4 as uuidv4 } from 'uuid'
import { Response, Request } from 'express'
import { AuthError } from '../../auth.error'
import { HashingService } from 'src/routes/auth/shared/services/common/hashing.service'
import { ICookieService, ITokenService } from 'src/routes/auth/shared/auth.types'
import { TypeOfVerificationCode } from 'src/routes/auth/shared/constants/auth.constants'
import { OtpService } from '../../modules/otp/otp.service'
import { User, Device, Role, UserProfile } from '@prisma/client'
import { AccessTokenPayloadCreate } from 'src/routes/auth/shared/auth.types'
import {
  COOKIE_SERVICE,
  DEVICE_SERVICE,
  HASHING_SERVICE,
  REDIS_SERVICE,
  SLT_SERVICE,
  TOKEN_SERVICE
} from 'src/shared/constants/injection.tokens'
import {
  UserAuthRepository,
  DeviceRepository,
  SessionRepository,
  UserWithProfileAndRole
} from 'src/routes/auth/shared/repositories'
import { I18nTranslations, I18nPath } from 'src/generated/i18n.generated'
import { RedisService } from 'src/providers/redis/redis.service'
import { SLTService } from 'src/routes/auth/shared/services/slt.service'
import { DeviceService } from 'src/routes/auth/shared/services/device.service'
import { SessionsService } from 'src/routes/auth/modules/sessions/sessions.service'
import { AuthVerificationService } from '../../services/auth-verification.service'
import { CompleteRegistrationDto, LoginDto } from './auth.dto'
import { ConfigService } from '@nestjs/config'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'

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

interface LoginParams {
  emailOrUsername: string
  password: string
  rememberMe?: boolean
  ip?: string
  userAgent?: string
}

@Injectable()
export class CoreService {
  private readonly logger = new Logger(CoreService.name)

  constructor(
    private readonly configService: ConfigService,
    private readonly i18nService: I18nService<I18nTranslations>,
    private readonly userAuthRepository: UserAuthRepository,
    private readonly deviceRepository: DeviceRepository,
    private readonly otpService: OtpService,
    private readonly sessionRepository: SessionRepository,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService,
    @Inject(DEVICE_SERVICE) private readonly deviceService?: DeviceService,
    @Inject(forwardRef(() => SessionsService)) private readonly sessionsService?: SessionsService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService?: AuthVerificationService
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
   * Khởi tạo đăng ký
   */
  async initiateRegistration(
    email: string,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<{ message: I18nPath; data: any }> {
    try {
      // Kiểm tra email đã tồn tại chưa
      await this.checkEmailNotExists(email)

      if (!this.authVerificationService) {
        throw AuthError.InternalServerError('AuthVerificationService is not available.')
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

      return {
        message: verificationResult.message as I18nPath,
        data: verificationResult.data
      }
    } catch (error) {
      this.logger.error(`[initiateRegistration] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError(error.message)
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
  ): Promise<{ message: I18nPath }> {
    if (!this.sltService) throw AuthError.InternalServerError('SLTService not available')

    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(
      sltCookie,
      ipAddress || 'unknown',
      userAgent || 'unknown',
      TypeOfVerificationCode.REGISTER
    )

    if (sltContext.metadata?.otpVerified !== 'true') {
      throw AuthError.InsufficientPermissions() // Hoặc một lỗi cụ thể hơn
    }

    // Lấy email từ metadata hoặc trực tiếp từ context
    const email = sltContext.metadata?.pendingEmail || sltContext.email
    if (!email) {
      throw AuthError.InternalServerError('Email is missing in SLT context')
    }

    // Kiểm tra email không tồn tại trong cơ sở dữ liệu
    await this.checkEmailNotExists(email)

    // Hoàn tất đăng ký với thông tin từ params
    await this.completeRegistration({
      email,
      password: params.password,
      firstName: params.firstName,
      lastName: params.lastName,
      username: params.username,
      phoneNumber: params.phoneNumber,
      ip: ipAddress,
      userAgent: userAgent
    })

    // Finalize SLT
    await this.sltService.finalizeSlt(sltContext.sltJti)
    this.logger.log(`[completeRegistrationWithSlt] Registration completed and SLT finalized for email: ${email}`)

    return {
      message: 'auth.Auth.Register.Success'
    }
  }

  /**
   * Hoàn tất đăng ký
   */
  async completeRegistration(params: Omit<RegisterUserParams, 'userId'> & { email: string }): Promise<void> {
    const { email, password, firstName, lastName, username, phoneNumber } = params

    if (!password) {
      throw AuthError.InvalidPassword()
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
    const finalUsername = username || (await this.generateUniqueUsername(email))

    // Tạo user mới thay vì cập nhật
    try {
      await this.userAuthRepository.createUser({
        email,
        password: hashedPassword,
        firstName,
        lastName,
        username: finalUsername,
        phoneNumber
        // User sẽ được tạo với trạng thái "ACTIVE" theo mặc định
      })
    } catch (error) {
      this.logger.error(`[completeRegistration] Error creating new user: ${error.message}`, error.stack)
      throw AuthError.InternalServerError('Failed to create user during registration')
    }
  }

  /**
   * Validate user credentials
   */
  async validateUser(
    emailOrUsername: string,
    password: string
  ): Promise<Omit<UserWithProfileAndRole, 'password'> | null> {
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
  async refreshToken(refreshToken: string, deviceInfo: any, res: Response): Promise<{ message: I18nPath }> {
    try {
      const { userAgent, ip } = deviceInfo

      // Xác minh refresh token
      const payload = await this.tokenService.verifyRefreshToken(refreshToken)

      // Kiểm tra token có trong blacklist không
      const isBlacklisted = await this.tokenService.isRefreshTokenJtiBlacklisted(payload.jti)
      if (isBlacklisted) {
        throw AuthError.InvalidRefreshToken()
      }

      // Lấy thông tin user mới nhất
      const user = await this.userAuthRepository.findById(payload.userId)
      if (!user) {
        throw AuthError.EmailNotFound()
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

      return {
        message: 'auth.Auth.Token.Refreshed'
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
  async logout(userId: number, sessionId: string, req?: Request, res?: Response): Promise<{ message: I18nPath }> {
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
            this.logger.warn(`Lỗi vô hiệu hóa access token khi logout: ${error.message}`)
          }
        }
      }

      return { message: 'auth.Auth.Logout.Success' }
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
    const now = new Date()
    const absoluteSessionLifetimeInSeconds =
      this.configService.get<number>('ABSOLUTE_SESSION_LIFETIME_MS', 30 * 24 * 60 * 60 * 1000) / 1000

    const expiresAtDate = new Date(now.getTime() + absoluteSessionLifetimeInSeconds * 1000)
    const sessionId = uuidv4()

    await this.sessionRepository.createSession({
      id: sessionId,
      userId: user.id,
      deviceId: device.id,
      createdAt: now.getTime(),
      expiresAt: expiresAtDate.getTime(),
      ipAddress: ipAddress ?? 'Unknown',
      userAgent: userAgent ?? 'Unknown'
    })

    try {
      const effectiveIsTrustedSession = isTrustedSession ?? (await this.deviceRepository.isDeviceTrustValid(device.id))

      const payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'> = {
        userId: user.id,
        email: user.email,
        roleId: user.role.id,
        roleName: user.role.name,
        deviceId: device.id,
        sessionId,
        jti: `access_${Date.now()}_${this.generateRandomId()}`,
        isDeviceTrustedInSession: effectiveIsTrustedSession
      }

      const accessToken = this.tokenService.signAccessToken(payload)
      const refreshToken = this.tokenService.signRefreshToken({
        ...payload,
        jti: `refresh_${Date.now()}_${this.generateRandomId()}`
      })

      const refreshCookieMaxAge = rememberMe
        ? this.configService.get<number>('security.jwt.refresh.rememberMeExpiresInSeconds', 30 * 24 * 60 * 60) * 1000
        : this.configService.get<number>('security.jwt.refresh.expiresInSeconds', 24 * 60 * 60) * 1000
      this.cookieService.setTokenCookies(res, accessToken, refreshToken, refreshCookieMaxAge)

      const userResponse = {
        id: user.id,
        username: user.userProfile?.username,
        avatar: user.userProfile?.avatar,
        isDeviceTrustedInSession: effectiveIsTrustedSession
      }

      return {
        message: 'auth.Auth.Login.Success',
        data: {
          user: userResponse
        }
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
   * Kiểm tra email chưa tồn tại
   */
  async checkEmailNotExists(email: string): Promise<void> {
    const existingUser = await this.userAuthRepository.findByEmail(email)
    if (existingUser) {
      throw AuthError.EmailAlreadyExists()
    }
  }

  /**
   * Tạo user tạm thời trong quá trình đăng ký
   */
  async createTemporaryUser(email: string): Promise<User> {
    try {
      // Tạo một temporary user với trạng thái PENDING
      const tempUser = await this.userAuthRepository.createUser({
        email: email,
        password: await this.hashingService.hash(`temp_${Date.now()}_${Math.random()}`)
        // Các trường khác có thể để mặc định hoặc để trống
      })

      return tempUser
    } catch (error) {
      this.logger.error(`[createTemporaryUser] Error creating temporary user: ${error.message}`, error.stack)
      throw AuthError.InternalServerError('Failed to create temporary user')
    }
  }

  /**
   * Tạo device tạm thời trong quá trình đăng ký
   */
  async createTemporaryDevice(userId: number, userAgent: string, ipAddress: string): Promise<Device> {
    try {
      // Tạo một temporary device
      const tempDevice = await this.deviceRepository.createDevice({
        userId: userId,
        userAgent: userAgent,
        ipAddress: ipAddress
      })

      return tempDevice
    } catch (error) {
      this.logger.error(`[createTemporaryDevice] Error creating temporary device: ${error.message}`, error.stack)
      throw AuthError.InternalServerError('Failed to create temporary device')
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
      throw AuthError.InternalServerError('AuthVerificationService is not available.')
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
    if (verificationResult.success && verificationResult.tokens) {
      return {
        message: verificationResult.message,
        data: {
          user: verificationResult.user
        }
      }
    }

    return {
      message: verificationResult.message,
      data: verificationResult.data
    }
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
      const userWithPassword = await this.userAuthRepository.findById(userId)
      if (!userWithPassword) {
        throw AuthError.EmailNotFound()
      }

      // Loại bỏ mật khẩu để đảm bảo an toàn
      const { password: _, ...user } = userWithPassword

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

      this.logger.debug(
        `[finalizeLoginAfterVerification] Calling finalizeLoginAndCreateTokens for user ${userId}, device ${deviceId}`
      )

      return this.finalizeLoginAndCreateTokens(user, device, rememberMe, res, ipAddress, userAgent, isDeviceTrustedNow)
    } catch (error) {
      this.logger.error(`[finalizeLoginAfterVerification] Error: ${error.message}`, error.stack)
      if (error instanceof AuthError) throw error
      throw AuthError.InternalServerError(error.message)
    }
  }
}
