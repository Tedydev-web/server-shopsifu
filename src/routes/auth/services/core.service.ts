import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Response, Request } from 'express'
import { v4 as uuidv4 } from 'uuid'

// Prisma Types
import { User, Device, Role, UserProfile } from '@prisma/client'

// Internal Services
import { HashingService } from 'src/shared/services/hashing.service'
import { EmailService } from 'src/shared/services/email.service'
import { DeviceFingerprintService } from 'src/shared/services/device-fingerprint.service'

// Auth Services
import { DeviceService } from './device.service'
import { SessionsService } from 'src/routes/auth/services/session.service'
import { AuthVerificationService } from './auth-verification.service'
import { UserService } from 'src/routes/user/user.service'

// Repositories
import { SessionRepository } from 'src/routes/auth/repositories'

// Types & Interfaces
import {
  ICookieService,
  ITokenService,
  ILoginFinalizerService,
  ILoginFinalizationPayload,
  ISLTService,
  AccessTokenPayloadCreate
} from 'src/routes/auth/auth.types'

// DTOs
import { CompleteRegistrationDto, LoginDto } from '../dtos/core.dto'

// Constants & Enums
import { TypeOfVerificationCode } from 'src/routes/auth/auth.constants'
import {
  COOKIE_SERVICE,
  DEVICE_SERVICE,
  HASHING_SERVICE,
  SLT_SERVICE,
  TOKEN_SERVICE,
  EMAIL_SERVICE,
  REDIS_SERVICE,
  DEVICE_FINGERPRINT_SERVICE
} from 'src/shared/constants/injection.tokens'

// Utils
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'

// Errors
import { AuthError } from '../auth.error'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { GlobalError } from 'src/shared/global.error'
import { DeviceRepository } from 'src/shared/repositories/device.repository'
import { UserRepository, UserWithProfileAndRole } from 'src/routes/user/user.repository'
import { ProfileRepository } from 'src/routes/profile/profile.repository'
import { RoleRepository } from 'src/routes/role/role.repository'
import { RedisService } from 'src/shared/providers/redis/redis.service'

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
  fingerprint?: string
}

@Injectable()
export class CoreService implements ILoginFinalizerService {
  private readonly logger = new Logger(CoreService.name)

  constructor(
    private readonly configService: ConfigService,
    private readonly userRepository: UserRepository,
    private readonly profileRepository: ProfileRepository,
    @Inject(forwardRef(() => RoleRepository)) private readonly roleRepository: RoleRepository,
    private readonly deviceRepository: DeviceRepository,
    private readonly sessionRepository: SessionRepository,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    @Inject(SLT_SERVICE) private readonly sltService: ISLTService,
    @Inject(DEVICE_FINGERPRINT_SERVICE) private readonly deviceFingerprintService: DeviceFingerprintService,
    @Inject(DEVICE_SERVICE) private readonly deviceService?: DeviceService,
    @Inject(forwardRef(() => SessionsService)) private readonly sessionsService?: SessionsService,
    @Inject(forwardRef(() => UserService)) private readonly userService?: UserService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService?: AuthVerificationService,
    @Inject(EMAIL_SERVICE) private readonly emailService?: EmailService,
    @Inject(REDIS_SERVICE) private readonly redisService?: RedisService
  ) {}

  private async generateUniqueUsername(baseUsername: string): Promise<string> {
    // Chuẩn hóa username: chỉ giữ chữ thường và số, tối đa 15 ký tự
    let username = baseUsername
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '')
      .substring(0, 15)

    const exists = await this.profileRepository.doesUsernameExist(username)

    if (exists) {
      // Thêm suffix ngẫu nhiên để đảm bảo tính duy nhất
      const randomSuffix = Math.floor(Math.random() * 10000)
      username = `${username.substring(0, 10)}${randomSuffix}`
    }

    return username
  }

  async initiateRegistration(email: string, ipAddress: string, userAgent: string, res: Response): Promise<any> {
    try {
      await this.checkEmailNotExists(email)

      if (!this.authVerificationService) {
        throw AuthError.ServiceNotAvailable('AuthVerificationService')
      }

      // Khởi tạo quá trình xác thực email mà không tạo user tạm thời
      const verificationResult = await this.authVerificationService.initiateVerification(
        {
          userId: 0, // Placeholder - sẽ được xử lý bởi SLT service
          deviceId: 0, // Placeholder - sẽ được xử lý bởi SLT service
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
      if (error instanceof ApiException) throw error
      throw GlobalError.InternalServerError()
    }
  }

  async completeRegistrationWithSlt(
    sltCookie: string,
    params: CompleteRegistrationDto,
    ipAddress?: string,
    userAgent?: string
  ): Promise<any> {
    // Validate password confirmation
    if (params.password !== params.confirmPassword) {
      throw AuthError.PasswordsNotMatch()
    }

    if (!this.sltService) throw AuthError.ServiceNotAvailable('SLTService')

    // Xác thực SLT token và lấy context
    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(
      sltCookie,
      ipAddress || 'unknown',
      userAgent || 'unknown',
      TypeOfVerificationCode.REGISTER
    )

    // Kiểm tra OTP đã được xác minh chưa
    if (sltContext.metadata?.otpVerified !== 'true') {
      throw AuthError.InsufficientPermissions()
    }

    // Lấy email từ SLT context
    const email = sltContext.metadata?.pendingEmail || sltContext.email
    if (!email) {
      throw AuthError.EmailMissingInSltContext()
    }

    // Double-check email chưa tồn tại
    await this.checkEmailNotExists(email)

    // Tạo user và profile mới trong database
    const newUser = await this.createUserAndProfile({
      email,
      password: params.password,
      firstName: params.firstName,
      lastName: params.lastName,
      username: params.username,
      phoneNumber: params.phoneNumber,
      ip: ipAddress,
      userAgent: userAgent,
      fingerprint: params.fingerprint
    })

    // Gửi email chào mừng (async, không block response)
    if (this.emailService) {
      await this.emailService.sendWelcomeEmail(email, {
        userName: newUser.userProfile?.username || email.split('@')[0]
      })
    }

    // 3. Create device and session
    const device = await this.getOrCreateDevice(newUser.id, ipAddress, userAgent, params.fingerprint)
    await this.createSessionForLogin(newUser.id, device.id, ipAddress, userAgent)

    // Kết thúc và xóa SLT token
    await this.sltService.finalizeSlt(sltContext.sltJti)

    return {
      message: 'auth.success.register.complete'
    }
  }

  async createUserAndProfile(
    params: Omit<RegisterUserParams, 'userId'> & { email: string }
  ): Promise<UserWithProfileAndRole> {
    const { email, password, firstName, lastName, username: providedUsername, phoneNumber } = params

    // 1. Validate email chưa tồn tại
    await this.checkEmailNotExists(email)

    // 2. Xử lý username - sử dụng username được cung cấp hoặc tạo tự động
    let finalUsername: string
    if (providedUsername) {
      const usernameExists = await this.profileRepository.doesUsernameExist(providedUsername)
      if (usernameExists) {
        throw AuthError.UsernameAlreadyExists(providedUsername)
      }
      finalUsername = providedUsername
    } else {
      // Tạo username tự động từ phần đầu email
      finalUsername = await this.generateUniqueUsername(email.split('@')[0])
    }

    // 3. Hash password để lưu trữ an toàn
    const hashedPassword = password ? await this.hashingService.hash(password) : undefined
    if (!hashedPassword) {
      throw GlobalError.InternalServerError('auth.error.passwordProcessingFailed')
    }

    // 4. Lấy default role 'Customer' cho user mới
    const customerRole = await this.roleRepository.findByName('Customer')
    if (!customerRole) {
      throw GlobalError.InternalServerError('auth.error.roleConfigurationError')
    }

    // 5. Tạo user với profile trong database (transaction)
    return this.userRepository.createWithProfile({
      email,
      password: hashedPassword,
      roleId: customerRole.id,
      username: finalUsername,
      firstName,
      lastName,
      phoneNumber
    })
  }

  async validateUser(
    emailOrUsername: string,
    password: string
  ): Promise<Omit<UserWithProfileAndRole, 'password' | 'role.permissions'>> {
    const user = await this.userRepository.findByEmailOrUsername(emailOrUsername)

    // Nếu không tìm thấy user với email/username này
    if (!user || !user.password) {
      throw AuthError.InvalidLoginCredentials()
    }

    // Kiểm tra mật khẩu
    const isPasswordValid = await this.hashingService.compare(password, user.password)
    if (!isPasswordValid) {
      throw AuthError.InvalidLoginCredentials()
    }

    // Loại bỏ password khỏi response để bảo mật
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password: userPassword, ...result } = user
    return result
  }

  async getOrCreateDevice(userId: number, ip?: string, userAgent?: string, fingerprint?: string): Promise<Device> {
    // More specific validation with better error messages
    if (!ip || ip.trim() === '') {
      throw AuthError.DeviceProcessingFailed()
    }

    if (!userAgent || userAgent.trim() === '') {
      throw AuthError.DeviceProcessingFailed()
    }

    return this.deviceRepository.upsertDevice(userId, userAgent, ip, fingerprint)
  }

  async refreshToken(req: Request, deviceInfo: { ipAddress: string; userAgent: string }, res: Response): Promise<any> {
    try {
      const refreshToken = this.tokenService.extractRefreshTokenFromRequest(req)
      if (!refreshToken) {
        throw AuthError.MissingRefreshToken()
      }

      // Xác minh tính hợp lệ của refresh token
      const payload = await this.tokenService.verifyRefreshToken(refreshToken)

      // Kiểm tra token có bị blacklist không
      const isBlacklisted = await this.tokenService.isRefreshTokenJtiBlacklisted(payload.jti)
      if (isBlacklisted) {
        throw AuthError.InvalidRefreshToken()
      }

      // Lấy thông tin user mới nhất từ database
      const user = await this.userRepository.findByIdWithDetails(payload.userId)
      if (!user) {
        throw GlobalError.NotFound('user')
      }

      // Đánh dấu refresh token cũ là đã sử dụng (one-time use)
      await this.tokenService.markRefreshTokenJtiAsUsed(payload.jti, payload.sessionId)

      // Tạo payload cho cặp token mới
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

      // Tạo cặp token mới
      const newAccessToken = this.tokenService.signAccessToken(newPayload)
      const newRefreshToken = this.tokenService.signRefreshToken({
        ...newPayload,
        jti: `refresh_${Date.now()}_${this.generateRandomId()}`
      })

      // Thiết lập cookie mới cho client
      this.cookieService.setTokenCookies(res, newAccessToken, newRefreshToken)

      return { message: 'auth.success.token.refreshed' }
    } catch (error) {
      this.cookieService.clearTokenCookies(res)
      if (error instanceof ApiException) throw error
      throw GlobalError.InternalServerError()
    }
  }

  async logout(userId: number, sessionId: string, req?: Request, res?: Response): Promise<{ message: string }> {
    try {
      // Xóa các cookie liên quan đến authentication
      if (res) {
        this.cookieService.clearTokenCookies(res)
        this.cookieService.clearSltCookie(res)

        // Xóa các cookie khác (trừ CSRF protection)
        const cookies = req?.cookies
        if (cookies) {
          Object.keys(cookies).forEach((cookieName) => {
            if (cookieName !== '_csrf' && cookieName !== 'xsrf-token') {
              res.clearCookie(cookieName, { path: '/' })
            }
          })
        }
      }

      if (this.sessionsService) {
        await this.sessionsService.invalidateSession(sessionId, 'logout')
      }

      // Vô hiệu hóa access token hiện tại
      if (req) {
        const accessToken = this.tokenService.extractTokenFromRequest(req)
        if (accessToken) {
          const payload = await this.tokenService.verifyAccessToken(accessToken)
          await this.tokenService.invalidateAccessTokenJti(payload.jti, payload.exp)
        }
      }

      return { message: 'auth.success.logout.success' }
    } catch (error) {
      if (error instanceof ApiException) throw error
      throw GlobalError.InternalServerError()
    }
  }

  async findUserByEmail(email: string): Promise<any> {
    return this.userRepository.findByEmailOrUsername(email)
  }

  async getDeviceById(deviceId: number): Promise<Device | null> {
    if (!deviceId) return null

    try {
      return this.deviceRepository.findById(deviceId)
    } catch {
      return null
    }
  }

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
      // Tạo session mới cho lần đăng nhập này
      const sessionId = await this.createSessionForLogin(user.id, device.id, ipAddress, userAgent)

      // Xác định trạng thái trusted của session
      const effectiveIsTrustedSession = isTrustedSession ?? (await this.deviceRepository.isDeviceTrustValid(device.id))

      // Tạo và thiết lập các token authentication
      this.generateAndSetAuthTokens(user, device.id, sessionId, effectiveIsTrustedSession, rememberMe, res)

      // Chỉ trả về các thông tin an toàn, cần thiết cho client
      const userResponse = {
        id: user.id,
        email: user.email,
        username: user.userProfile?.username,
        avatar: user.userProfile?.avatar,
        isDeviceTrustedInSession: effectiveIsTrustedSession
      }

      return {
        message: 'auth.success.login.success',
        data: userResponse
      }
    } catch (error) {
      if (error instanceof ApiException) throw error
      throw GlobalError.InternalServerError()
    }
  }

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

    return sessionId
  }

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

  private generateRandomId(length: number = 12): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    let result = ''
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length))
    }
    return result
  }

  async checkEmailNotExists(email: string): Promise<void> {
    const existingUser = await this.userRepository.findByEmail(email)
    if (existingUser) {
      throw AuthError.EmailAlreadyExists()
    }
  }

  async initiateLogin(loginDto: LoginDto, ip: string, userAgent: string, res: Response) {
    // 1. Validate user credentials
    const user = await this.validateUser(loginDto.email, loginDto.password)

    // 2. Get or create a device record for the user
    const device = await this.getOrCreateDevice(user.id, ip, userAgent, loginDto.fingerprint)

    // 3. Determine if the login requires further verification
    const reverifyKey = RedisKeyManager.getUserReverifyNextLoginKey(user.id)
    const needsReverification = await this.redisService.get(reverifyKey)

    if (needsReverification) {
      // Xóa flag sau khi đọc để chỉ có hiệu lực một lần
      await this.redisService.del(reverifyKey)
    }

    if (!this.authVerificationService) {
      throw AuthError.ServiceNotAvailable('AuthVerificationService')
    }

    // 4. Khởi tạo quá trình xác thực (OTP/2FA nếu cần)
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

    return verificationResult
  }

  async initiateLoginWithEnhancedDevice(loginDto: LoginDto, req: Request, res: Response) {
    // 1. Validate user credentials
    const user = await this.validateUser(loginDto.email, loginDto.password)

    // 2. Extract enhanced device information
    const enhancedDeviceInfo = await this.deviceFingerprintService.extractDeviceInfo(req)

    // 3. Create or update device with enhanced fingerprinting
    const device = await this.deviceRepository.upsertDevice(
      user.id,
      enhancedDeviceInfo.userAgent,
      enhancedDeviceInfo.ipAddress,
      enhancedDeviceInfo.fingerprint
    )

    // 4. Determine if the login requires further verification
    const reverifyKey = RedisKeyManager.getUserReverifyNextLoginKey(user.id)
    const needsReverification = await this.redisService.get(reverifyKey)

    if (needsReverification) {
      // Xóa flag sau khi đọc để chỉ có hiệu lực một lần
      await this.redisService.del(reverifyKey)
    }

    if (!this.authVerificationService) {
      throw AuthError.ServiceNotAvailable('AuthVerificationService')
    }

    // 5. Khởi tạo quá trình xác thực (OTP/2FA nếu cần)
    const verificationResult = await this.authVerificationService.initiateVerification(
      {
        userId: user.id,
        deviceId: device.id,
        email: user.email,
        ipAddress: enhancedDeviceInfo.ipAddress,
        userAgent: enhancedDeviceInfo.userAgent,
        purpose: TypeOfVerificationCode.LOGIN,
        rememberMe: loginDto.rememberMe,
        metadata: {
          from: 'login',
          forceVerification: !!needsReverification,
          deviceInfo: enhancedDeviceInfo
        }
      },
      res
    )

    return verificationResult
  }

  async finalizeLoginAfterVerification(payload: ILoginFinalizationPayload, res: Response): Promise<any> {
    const { userId, deviceId, rememberMe, ipAddress, userAgent } = payload
    try {
      // Lấy thông tin user đầy đủ từ database
      const user = await this.userRepository.findByIdWithDetails(userId)
      if (!user) {
        throw GlobalError.NotFound('user')
      }

      // Lấy thông tin thiết bị
      const device = await this.deviceRepository.findById(deviceId)
      if (!device) {
        throw AuthError.DeviceNotFound()
      }

      // Kiểm tra trạng thái trusted của thiết bị trước khi đăng nhập
      const wasDeviceTrusted = await this.deviceRepository.isDeviceTrustValid(deviceId)

      // Xác định trạng thái trusted sau đăng nhập (nếu rememberMe = true thì trust thiết bị)
      const isDeviceTrustedNow = rememberMe || wasDeviceTrusted

      // Hoàn tất đăng nhập và tạo token
      const loginResult = await this.finalizeLoginAndCreateTokens(
        user,
        device,
        rememberMe,
        res,
        ipAddress,
        userAgent,
        isDeviceTrustedNow
      )

      // Gửi thông báo nếu đăng nhập trên thiết bị chưa được tin cậy
      if (!wasDeviceTrusted && this.deviceService) {
        // Chạy bất đồng bộ để không block response
        void this.deviceService.notifyLoginOnUntrustedDevice(user, deviceId, ipAddress, userAgent)
      }

      return loginResult
    } catch (error) {
      if (error instanceof ApiException) throw error
      throw GlobalError.InternalServerError()
    }
  }
}
