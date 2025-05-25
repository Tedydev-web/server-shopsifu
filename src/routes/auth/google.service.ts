import { Injectable, Logger } from '@nestjs/common'
import { OAuth2Client } from 'google-auth-library'
import { google } from 'googleapis'
import { GoogleAuthStateType } from 'src/routes/auth/auth.model'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { AuthService } from 'src/routes/auth/auth.service'
import { GoogleUserInfoException } from 'src/routes/auth/auth.error'
import { RolesService } from 'src/routes/auth/roles.service'
import envConfig from 'src/shared/config'
import { HashingService } from 'src/shared/services/hashing.service'
import { v4 as uuidv4 } from 'uuid'
import { DeviceService } from 'src/routes/auth/providers/device.service'
import { TypeOfVerificationCode } from './constants/auth.constants'
import { OtpService } from 'src/routes/auth/providers/otp.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { TokenService } from 'src/routes/auth/providers/token.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import ms from 'ms'

@Injectable()
export class GoogleService {
  private oauth2Client: OAuth2Client
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authService: AuthService,
    private readonly deviceService: DeviceService,
    private readonly otpService: OtpService,
    private readonly prismaService: PrismaService,
    private readonly i18nService: I18nService,
    private readonly tokenService: TokenService,
    private readonly redisService: RedisService
  ) {
    this.oauth2Client = new google.auth.OAuth2(
      envConfig.GOOGLE_CLIENT_ID,
      envConfig.GOOGLE_CLIENT_SECRET,
      envConfig.GOOGLE_REDIRECT_URI
    )
  }
  getAuthorizationUrl({ userAgent, ip }: Omit<GoogleAuthStateType, 'rememberMe'>) {
    const scope = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']
    const stateObject: Omit<GoogleAuthStateType, 'rememberMe'> = {
      userAgent,
      ip
    }
    const stateString = Buffer.from(JSON.stringify(stateObject)).toString('base64')
    const url = this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope,
      include_granted_scopes: true,
      state: stateString,
      prompt: 'select_account'
    })
    return { url }
  }
  async googleCallback({
    code,
    state,
    userAgent = 'Unknown',
    ip = 'Unknown'
  }: {
    code: string
    state: string
    userAgent?: string
    ip?: string
  }) {
    const currentLang = I18nContext.current()?.lang
    try {
      try {
        if (state) {
          const clientInfo = JSON.parse(Buffer.from(state, 'base64').toString()) as Omit<
            GoogleAuthStateType,
            'rememberMe'
          >
          userAgent = clientInfo.userAgent || userAgent
          ip = clientInfo.ip || ip
        }
      } catch (error) {
        console.error('Error parsing state', error)
      }
      const { tokens } = await this.oauth2Client.getToken(code)
      this.oauth2Client.setCredentials(tokens)

      const ticket = await this.oauth2Client.verifyIdToken({
        idToken: tokens.id_token!,
        audience: envConfig.GOOGLE_CLIENT_ID
      })

      const payload = ticket.getPayload()
      if (!payload || !payload.email) {
        throw GoogleUserInfoException
      }

      let decodedState: GoogleAuthStateType | null = null
      try {
        decodedState = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'))
      } catch (error) {
        // Bỏ qua lỗi parse state, sử dụng userAgent và ip từ tham số
      }

      const effectiveUserAgent = decodedState?.userAgent || userAgent
      const effectiveIp = decodedState?.ip || ip
      const rememberMe = decodedState?.rememberMe || false

      let user = await this.prismaService.user.findUnique({
        where: { email: payload.email },
        include: { role: true }
      })

      const clientRoleId = await this.rolesService.getClientRoleId()

      if (!user) {
        user = await this.prismaService.user.create({
          data: {
            email: payload.email!,
            name: payload.name || 'Google User',
            password: await this.hashingService.hash(uuidv4()),
            phoneNumber: '', // payload.phone_number is not standard, initialize as empty
            avatar: payload.picture,
            status: 'ACTIVE',
            roleId: clientRoleId
          },
          include: { role: true }
        })
      } else if (!user.role) {
        user = await this.prismaService.user.update({
          where: { id: user.id },
          data: { roleId: clientRoleId },
          include: { role: true }
        })
      }

      const device = await this.deviceService.findOrCreateDevice({
        userId: user.id,
        userAgent: effectiveUserAgent,
        ip: effectiveIp
      })

      // Kiểm tra session hợp lệ
      if (!this.deviceService.isSessionValid(device)) {
        // Nếu session không hợp lệ, không cần 2FA, client nên xử lý như một lỗi đăng nhập
        // hoặc yêu cầu đăng nhập lại. Chúng ta sẽ không cấp token.
        // Có thể throw một lỗi cụ thể ở đây nếu cần.
        console.warn(
          `[GoogleService googleCallback] Absolute session lifetime exceeded for user ${String(user.id)}, device ${String(device.id)}.`
        )
        // Thay vì throw, trả về cấu trúc lỗi để controller xử lý redirect
        const sessionExpiredMessage = await this.i18nService.translate(
          'error.Error.Auth.Session.AbsoluteLifetimeExceeded',
          { lang: currentLang }
        )
        return {
          errorCode: 'session_expired',
          errorMessage: sessionExpiredMessage,
          redirectToError: true
        }
      }

      // Kiểm tra 2FA
      if (user.twoFactorEnabled && user.twoFactorSecret && user.twoFactorMethod) {
        if (device.isTrusted) {
          // Thiết bị tin cậy và session hợp lệ, bỏ qua 2FA
          console.debug(
            `[GoogleService googleCallback] Device ${String(device.id)} is trusted for user ${String(user.id)}. Skipping 2FA.`
          )
        } else {
          // Thiết bị không tin cậy, yêu cầu 2FA
          const loginSessionToken = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
            return this.otpService.createOtpToken({
              email: user.email,
              type: TypeOfVerificationCode.LOGIN_2FA,
              userId: user.id,
              deviceId: device.id,
              metadata: { rememberMe: false },
              tx
            })
          })

          return {
            message: 'Auth.Login.2FARequired',
            loginSessionToken: loginSessionToken,
            twoFactorMethod: user.twoFactorMethod,
            isGoogleAuth: true
          }
        }
      }

      // Tạo session mới
      const sessionId = uuidv4()
      const now = new Date()

      const sessionData: Record<string, string | number | boolean> = {
        userId: user.id,
        deviceId: device.id,
        ipAddress: effectiveIp,
        userAgent: effectiveUserAgent,
        createdAt: now.toISOString(),
        lastActiveAt: now.toISOString(),
        isTrusted: device.isTrusted, // Google login có thể coi là trusted hoặc cần flow riêng
        rememberMe: rememberMe,
        roleId: user.roleId,
        roleName: user.role.name
      }

      // Gọi TokenService trực tiếp
      const { accessToken, refreshToken, maxAgeForRefreshTokenCookie, accessTokenJti } =
        await this.tokenService.generateTokens(
          {
            userId: user.id,
            deviceId: device.id,
            roleId: user.roleId,
            roleName: user.role.name,
            sessionId // Thêm sessionId
          },
          undefined, // Không có transaction Prisma ở đây
          rememberMe
        )

      sessionData.currentAccessTokenJti = accessTokenJti
      sessionData.currentRefreshTokenJti = refreshToken

      const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${user.id}`
      const absoluteSessionLifetimeSeconds = Math.floor(envConfig.ABSOLUTE_SESSION_LIFETIME_MS / 1000)

      await this.redisService.pipeline((pipeline) => {
        pipeline.hmset(sessionKey, sessionData)
        pipeline.expire(sessionKey, absoluteSessionLifetimeSeconds)
        pipeline.sadd(userSessionsKey, sessionId)
        return pipeline
      })

      return {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role.name
        },
        accessToken,
        refreshToken,
        maxAgeForRefreshTokenCookie
      }
    } catch (error) {
      console.error('Error in googleCallback', error)
      const errorCode = (error as any).code || 'auth_error'
      const defaultMessage = await this.i18nService.translate('error.Error.Auth.Google.CallbackErrorGeneric', {
        lang: currentLang
      })
      const errorMessage =
        error instanceof Error
          ? encodeURIComponent(error.message) // Giữ lại thông báo lỗi cụ thể nếu có
          : encodeURIComponent(defaultMessage)

      return {
        errorCode,
        errorMessage,
        redirectToError: true
      }
    }
  }
}
