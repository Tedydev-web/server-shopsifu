import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { OAuth2Client } from 'google-auth-library'
import { google } from 'googleapis'
import { GoogleAuthStateType } from 'src/routes/auth/auth.model'
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
import { Prisma } from '@prisma/client'
import { ApiException } from 'src/shared/exceptions/api.exception'

@Injectable()
export class GoogleService {
  private readonly logger = new Logger(GoogleService.name)
  private oauth2Client: OAuth2Client
  constructor(
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
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
      envConfig.GOOGLE_CLIENT_REDIRECT_URI
    )
  }
  getAuthorizationUrl({ userAgent, ip }: Omit<GoogleAuthStateType, 'rememberMe'>): { url: string; nonce: string } {
    const scope = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']

    const nonce = uuidv4()

    const stateObject: Omit<GoogleAuthStateType, 'rememberMe'> & { nonce: string } = {
      userAgent,
      ip,
      nonce
    }
    const stateString = Buffer.from(JSON.stringify(stateObject)).toString('base64')
    const url = this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope,
      include_granted_scopes: true,
      state: stateString,
      prompt: 'select_account'
    })
    return { url, nonce }
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
      } catch (parseError) {
        console.error('Error parsing state', parseError)
      }
      const { tokens } = await this.oauth2Client.getToken(code)
      this.oauth2Client.setCredentials(tokens)

      const ticket = await this.oauth2Client.verifyIdToken({
        idToken: tokens.id_token!,
        audience: envConfig.GOOGLE_CLIENT_ID
      })

      const payload = ticket.getPayload()
      if (!payload || !payload.email || !payload.sub) {
        this.logger.error('[GoogleCallback] Invalid payload from Google: missing email or sub (googleId).', payload)
        throw GoogleUserInfoException
      }

      const googleUserId = payload.sub

      let stateFromServer: (Omit<GoogleAuthStateType, 'rememberMe'> & { nonce: string }) | null = null
      try {
        if (state) {
          stateFromServer = JSON.parse(Buffer.from(state, 'base64').toString('utf-8')) as Omit<
            GoogleAuthStateType,
            'rememberMe'
          > & { nonce: string }
          userAgent = stateFromServer?.userAgent || userAgent
          ip = stateFromServer?.ip || ip
        }
      } catch (parseError) {
        this.logger.warn(
          '[GoogleCallback] Could not parse state string from Google, or state was empty. Using request IP/UserAgent.',
          parseError
        )
      }

      const rememberMe = false

      let user = await this.prismaService.user.findUnique({
        where: { googleId: googleUserId },
        include: { role: true }
      })

      const clientRoleId = await this.rolesService.getClientRoleId()

      if (!user) {
        const userByEmail = await this.prismaService.user.findUnique({
          where: { email: payload.email },
          include: { role: true }
        })

        if (userByEmail) {
          if (userByEmail.googleId && userByEmail.googleId !== googleUserId) {
            this.logger.error(
              `[GoogleCallback] User with email ${payload.email} (ID: ${userByEmail.id}) is already linked to a different Google ID (${userByEmail.googleId}). Attempted to link with ${googleUserId}.`
            )
            throw new ApiException(
              HttpStatus.CONFLICT,
              'GoogleAccountConflict',
              'error.Error.Auth.Google.AccountConflict'
            )
          }

          this.logger.log(
            `[GoogleCallback] User with email ${payload.email} (ID: ${userByEmail.id}) found. Linking with Google ID ${googleUserId}.`
          )
          user = await this.prismaService.user.update({
            where: { id: userByEmail.id },
            data: {
              googleId: googleUserId,
              ...(payload.picture && (!userByEmail.avatar || userByEmail.avatar !== payload.picture)
                ? { avatar: payload.picture }
                : {}),
              ...(!userByEmail.roleId || !userByEmail.role ? { role: { connect: { id: clientRoleId } } } : {})
            },
            include: { role: true }
          })
        } else {
          this.logger.log(
            `[GoogleCallback] No user found for Google ID ${googleUserId} or email ${payload.email}. Creating new user.`
          )
          user = await this.prismaService.user.create({
            data: {
              email: payload.email,
              name: payload.name || 'Google User',
              password: await this.hashingService.hash(uuidv4()),
              phoneNumber: '',
              avatar: payload.picture,
              status: 'ACTIVE',
              role: { connect: { id: clientRoleId } },
              googleId: googleUserId
            },
            include: { role: true }
          })
        }
      } else {
        this.logger.log(`[GoogleCallback] User found by Google ID ${googleUserId}: ${user.email} (ID: ${user.id}).`)
        const updates: Prisma.UserUpdateInput = {}
        if (payload.email && user.email !== payload.email) {
          this.logger.warn(
            `[GoogleCallback] User ${user.id} (googleId: ${googleUserId}) has different email in DB (${user.email}) and Google (${payload.email}). Email NOT updated automatically to avoid conflicts. Manual review might be needed if this is a concern.`
          )
        }
        if (payload.name && user.name !== payload.name) {
          updates.name = payload.name
        }
        if (payload.picture && user.avatar !== payload.picture) {
          updates.avatar = payload.picture
        }
        if (!user.roleId || !user.role) {
          updates.role = { connect: { id: clientRoleId } }
        }

        if (Object.keys(updates).length > 0) {
          this.logger.log(`[GoogleCallback] Updating user ${user.id} details from Google:`, updates)
          user = await this.prismaService.user.update({
            where: { id: user.id },
            data: updates,
            include: { role: true }
          })
        }
      }

      if (!user.role) {
        this.logger.warn(`[GoogleCallback] User ${user.id} still has no role after processing. Forcing client role.`)
        user = await this.prismaService.user.update({
          where: { id: user.id },
          data: { role: { connect: { id: clientRoleId } } },
          include: { role: true }
        })
      }

      const device = await this.deviceService.findOrCreateDevice({
        userId: user.id,
        userAgent: userAgent,
        ip: ip
      })

      if (user.twoFactorEnabled && user.twoFactorSecret && user.twoFactorMethod) {
        if (device.isTrusted) {
          console.debug(
            `[GoogleService googleCallback] Device ${String(device.id)} is trusted for user ${String(user.id)}. Skipping 2FA.`
          )
        } else {
          const loginSessionToken = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
            return this.otpService.createLoginSessionToken({
              email: user.email,
              type: TypeOfVerificationCode.LOGIN_2FA,
              userId: user.id,
              deviceId: device.id,
              metadata: { rememberMe: false, isGoogleAuth: true },
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

      const sessionId = uuidv4()
      const now = new Date()

      const sessionData: Record<string, string | number | boolean> = {
        userId: user.id,
        deviceId: device.id,
        ipAddress: ip,
        userAgent: userAgent,
        createdAt: now.toISOString(),
        lastActiveAt: now.toISOString(),
        isTrusted: device.isTrusted,
        rememberMe: rememberMe,
        roleId: user.roleId,
        roleName: user.role.name
      }

      const { accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie, accessTokenJti } =
        await this.tokenService.generateTokens(
          {
            userId: user.id,
            deviceId: device.id,
            roleId: user.roleId,
            roleName: user.role.name,
            sessionId
          },
          undefined,
          rememberMe
        )

      sessionData.currentAccessTokenJti = accessTokenJti
      sessionData.currentRefreshTokenJti = refreshTokenJti

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
        refreshTokenJti,
        maxAgeForRefreshTokenCookie
      }
    } catch (error) {
      console.error('Error in googleCallback', error)
      const errorCode = error.code || 'auth_error'
      const defaultMessage = await this.i18nService.translate('error.Error.Auth.Google.CallbackErrorGeneric', {
        lang: currentLang
      })
      const errorMessage =
        error instanceof Error ? encodeURIComponent(error.message) : encodeURIComponent(defaultMessage)

      return {
        errorCode,
        errorMessage,
        redirectToError: true
      }
    }
  }
}
