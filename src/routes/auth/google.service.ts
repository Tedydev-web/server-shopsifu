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
import { Prisma, Role, User, Device, TwoFactorMethodType as PrismaTwoFactorMethodType } from '@prisma/client'
import { ApiException } from 'src/shared/exceptions/api.exception'

export interface GoogleCallbackSuccessResult {
  user: User & { role: Role }
  device: Device
  requiresTwoFactorAuth: boolean
  requiresUntrustedDeviceVerification: boolean
  twoFactorMethod?: PrismaTwoFactorMethodType | null
  isLoginViaGoogle: true
  message: string
}

export interface GoogleCallbackErrorResult {
  errorCode: string
  errorMessage: string
  redirectToError: true
}

export type GoogleCallbackReturnType = GoogleCallbackSuccessResult | GoogleCallbackErrorResult

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
  }): Promise<GoogleCallbackReturnType> {
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
        return {
          errorCode: 'INVALID_PAYLOAD',
          errorMessage: await this.i18nService.translate('error.Error.Auth.Google.UserInfoFailed', {
            lang: currentLang,
            defaultValue: 'Failed to retrieve user information from Google.'
          }),
          redirectToError: true
        }
      }

      const googleUserId = payload.sub

      let stateFromServer: { userAgent?: string; ip?: string; nonce: string } | null = null
      try {
        if (state) {
          const parsedState = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'))
          if (
            parsedState &&
            typeof parsedState === 'object' &&
            parsedState !== null &&
            'nonce' in parsedState &&
            typeof parsedState.nonce === 'string'
          ) {
            stateFromServer = {
              nonce: parsedState.nonce,
              userAgent: typeof parsedState.userAgent === 'string' ? parsedState.userAgent : undefined,
              ip: typeof parsedState.ip === 'string' ? parsedState.ip : undefined
            }
            userAgent = stateFromServer?.userAgent || userAgent
            ip = stateFromServer?.ip || ip
          } else {
            this.logger.warn('[GoogleCallback] Parsed state object is not in the expected format or missing nonce.')
          }
        }
      } catch (parseError) {
        this.logger.warn(
          '[GoogleCallback] Could not parse state string from Google, or state was empty. Using request IP/UserAgent.',
          parseError
        )
      }

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
            return {
              errorCode: 'ACCOUNT_CONFLICT',
              errorMessage: await this.i18nService.translate('error.Error.Auth.Google.AccountConflict', {
                lang: currentLang,
                defaultValue: 'This email is already linked to a different Google account.'
              }),
              redirectToError: true
            }
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
            `[GoogleCallback] User ${user.id} (googleId: ${googleUserId}) has different email in DB (${user.email}) and Google (${payload.email}). Email NOT updated automatically. Consider implications or manual review.`
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

      const requiresTwoFactorAuth = !!(
        user.twoFactorEnabled &&
        user.twoFactorSecret &&
        user.twoFactorMethod &&
        !device.isTrusted
      )
      const requiresUntrustedDeviceVerification = !user.twoFactorEnabled && !device.isTrusted

      this.logger.log(
        `[GoogleCallback] User: ${user.id}, Device: ${device.id} (isTrusted: ${device.isTrusted}), 2FA Enabled: ${user.twoFactorEnabled}, Requires 2FA: ${requiresTwoFactorAuth}, Requires Untrusted Verification: ${requiresUntrustedDeviceVerification}`
      )

      return {
        user,
        device,
        requiresTwoFactorAuth,
        requiresUntrustedDeviceVerification,
        twoFactorMethod: user.twoFactorMethod,
        isLoginViaGoogle: true,
        message: 'Google authentication successful. Proceed to security checks.'
      }
    } catch (error) {
      this.logger.error('[GoogleCallback] Error processing Google callback:', error)
      const resolveErrorCode = (): string => {
        if (error instanceof ApiException) {
          return error.getStatus().toString()
        }
        if (
          typeof error === 'object' &&
          error !== null &&
          'code' in error &&
          typeof (error as { code?: unknown }).code === 'string'
        ) {
          return (error as { code: string }).code
        }
        return 'AUTH_ERROR_GOOGLE_CALLBACK'
      }
      const errorCode = resolveErrorCode()

      let errorMessageKey = 'error.Error.Auth.Google.CallbackErrorGeneric'
      if (error instanceof ApiException) {
        const errorResponse = error.getResponse()
        if (typeof errorResponse === 'string') {
          errorMessageKey = errorResponse
        } else if (typeof errorResponse === 'object' && errorResponse !== null && 'messageKey' in errorResponse) {
          const potentialMessageKey = (errorResponse as { messageKey?: any }).messageKey
          if (typeof potentialMessageKey === 'string') {
            errorMessageKey = potentialMessageKey
          }
        }
      }

      const translatedMessageFromService: unknown = await this.i18nService.translate(errorMessageKey, {
        lang: currentLang,
        defaultValue: 'An unexpected error occurred during Google Sign-In. Please try again.'
      })

      let finalErrorMessage: string
      if (typeof translatedMessageFromService === 'string') {
        finalErrorMessage = translatedMessageFromService
      } else {
        this.logger.error(
          '[GoogleCallback] i18nService.translate did not return a string for key:',
          errorMessageKey,
          'Received:',
          translatedMessageFromService
        )
        finalErrorMessage = 'An unexpected error occurred during Google Sign-In. Please try again.'
      }

      return {
        errorCode,
        errorMessage: finalErrorMessage,
        redirectToError: true
      }
    }
  }
}
