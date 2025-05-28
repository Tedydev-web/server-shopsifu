import { Injectable, HttpStatus, Logger } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { LoginBodyType, RegisterBodyType, TwoFactorVerifyBodyType } from 'src/routes/auth/auth.model'
import { Response, Request } from 'express'
import {
  AbsoluteSessionLifetimeExceededException,
  DeviceMismatchException,
  DeviceSetupFailedException,
  EmailAlreadyExistsException,
  EmailNotFoundException,
  InvalidPasswordException,
  MissingRefreshTokenException,
  SessionNotFoundException,
  InvalidRefreshTokenException
} from 'src/routes/auth/auth.error'
import { AuditLogData, AuditLogStatus, AuditLogService } from 'src/routes/audit-log/audit-log.service'
import { isUniqueConstraintPrismaError } from 'src/shared/utils/type-guards.utils'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { Device, Prisma, User, UserStatus } from '@prisma/client'
import { TypeOfVerificationCode, TwoFactorMethodType } from '../constants/auth.constants'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { v4 as uuidv4 } from 'uuid'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import envConfig from 'src/shared/config'
import ms from 'ms'
import { GeolocationData, GeolocationService } from 'src/shared/services/geolocation.service'
import { SessionManagementService } from './session-management.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { HashingService } from 'src/shared/services/hashing.service'
import { RolesService } from '../roles.service'
import { AuthRepository } from '../auth.repo'
import { SharedUserRepository } from '../repositories/shared-user.repo'
import { EmailService } from '../providers/email.service'
import { TokenService } from '../providers/token.service'
import { TwoFactorService } from '../providers/2fa.service'
import { OtpService } from '../providers/otp.service'
import { DeviceService } from '../providers/device.service'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { JwtService } from '@nestjs/jwt'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { ReverifyPasswordBodyType } from '../auth.dto'
import { SltContextData } from '../providers/otp.service'
import { MaxVerificationAttemptsExceededException, InvalidOTPException } from '../auth.error'

const MAX_OTP_VERIFY_ATTEMPTS = 5

@Injectable()
export class AuthenticationService extends BaseAuthService {
  private readonly logger = new Logger(AuthenticationService.name)

  constructor(
    prismaService: PrismaService,
    hashingService: HashingService,
    rolesService: RolesService,
    authRepository: AuthRepository,
    sharedUserRepository: SharedUserRepository,
    emailService: EmailService,
    tokenService: TokenService,
    twoFactorService: TwoFactorService,
    auditLogService: AuditLogService,
    otpService: OtpService,
    deviceService: DeviceService,
    i18nService: I18nService,
    redisService: RedisService,
    geolocationService: GeolocationService,
    jwtService: JwtService,
    private readonly sessionManagementService: SessionManagementService
  ) {
    super(
      prismaService,
      hashingService,
      rolesService,
      authRepository,
      sharedUserRepository,
      emailService,
      tokenService,
      twoFactorService,
      auditLogService,
      otpService,
      deviceService,
      i18nService,
      redisService,
      geolocationService,
      jwtService
    )
  }

  async register(body: RegisterBodyType & { userAgent?: string; ip?: string }) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'USER_REGISTER_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        otpTokenProvided: !!body.otpToken,
        nameProvided: !!body.name,
        phoneNumberProvided: !!body.phoneNumber
      }
    }

    try {
      const user = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        const verificationPayload = await this.otpService.validateVerificationToken(
          body.otpToken,
          TypeOfVerificationCode.REGISTER,
          body.email
        )

        if (verificationPayload.userId) {
          auditLogEntry.userId = verificationPayload.userId
        }
        auditLogEntry.details.verificationTokenDeviceId = verificationPayload.deviceId
        auditLogEntry.details.jwtJti = verificationPayload.jti

        if (verificationPayload.deviceId && body.userAgent && body.ip) {
          const isValidDevice = await this.deviceService.validateDevice(
            verificationPayload.deviceId,
            body.userAgent,
            body.ip,
            tx
          )
          if (!isValidDevice) {
            auditLogEntry.errorMessage = DeviceMismatchException.message
            auditLogEntry.details.reason = 'DEVICE_MISMATCH_ON_REGISTER'
            auditLogEntry.details.validatedDeviceId = verificationPayload.deviceId
            throw DeviceMismatchException
          }
          auditLogEntry.details.deviceValidatedOnRegister = true
        }

        const clientRoleId = await this.rolesService.getClientRoleId()
        const hashedPassword = await this.hashingService.hash(body.password)

        const existingUserCheck = await tx.user.findUnique({ where: { email: body.email }, select: { id: true } })
        if (existingUserCheck) {
          auditLogEntry.errorMessage = EmailAlreadyExistsException.message
          auditLogEntry.details.reason = 'EMAIL_ALREADY_EXISTS_PRE_CREATE_CHECK'
        }

        const createdUser = await this.authRepository.createUser(
          {
            email: body.email,
            name: body.name,
            phoneNumber: body.phoneNumber,
            password: hashedPassword,
            roleId: clientRoleId,
            status: UserStatus.ACTIVE
          },
          tx
        )

        auditLogEntry.userId = createdUser.id
        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'USER_REGISTER_SUCCESS'
        auditLogEntry.details.roleIdAssigned = clientRoleId

        return createdUser
      })
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return user
    } catch (error) {
      if (
        isUniqueConstraintPrismaError(error) ||
        (auditLogEntry.details.reason === 'EMAIL_ALREADY_EXISTS_PRE_CREATE_CHECK' && !auditLogEntry.errorMessage)
      ) {
        auditLogEntry.errorMessage = EmailAlreadyExistsException.message
        auditLogEntry.details.reason = 'EMAIL_ALREADY_EXISTS'
      } else if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during registration'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      if (isUniqueConstraintPrismaError(error)) {
        throw EmailAlreadyExistsException
      }
      throw error
    }
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }, res?: Response) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'USER_LOGIN_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        rememberMeRequested: body.rememberMe
      }
    }
    try {
      const user = await this.prismaService.user.findUnique({
        where: { email: body.email },
        include: { role: true }
      })
      if (!user) {
        auditLogEntry.errorMessage = EmailNotFoundException.message
        auditLogEntry.details.reason = 'USER_NOT_FOUND'
        throw EmailNotFoundException
      }
      auditLogEntry.userId = user.id

      const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
      if (!isPasswordMatch) {
        this.logger.warn('[DEBUG AuthenticationService login] Invalid password for user:', user.email)
        auditLogEntry.errorMessage = InvalidPasswordException.message
        auditLogEntry.details.reason = 'INVALID_PASSWORD'
        throw InvalidPasswordException
      }

      let device: Device
      try {
        device = await this.deviceService.findOrCreateDevice({
          userId: user.id,
          userAgent: body.userAgent,
          ip: body.ip
        })
        auditLogEntry.details.deviceId = device.id
      } catch (error) {
        this.logger.error('[DEBUG AuthenticationService login] Error creating/finding device:', error)
        auditLogEntry.errorMessage = DeviceSetupFailedException.message
        auditLogEntry.details.deviceError = 'DeviceSetupFailed'
        throw DeviceSetupFailedException
      }

      const shouldAskToTrustDevice = !device.isTrusted
      const sessionId = uuidv4()
      const now = new Date()

      const geoLocation: GeolocationData | null = this.geolocationService.lookup(body.ip)
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object' && geoLocation) {
        auditLogEntry.details.location = `${geoLocation.city || 'N/A'}, ${geoLocation.country || 'N/A'}`
      }

      if (user.twoFactorEnabled && user.twoFactorSecret && user.twoFactorMethod && !device.isTrusted) {
        auditLogEntry.details.twoFactorMethod = user.twoFactorMethod
        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.notes = '2FA required: Device not trusted.'
        await this.auditLogService.record(auditLogEntry as AuditLogData)

        const sltJwt = await this.otpService.initiateOtpWithSltCookie({
          email: user.email,
          userId: user.id,
          deviceId: device.id,
          ipAddress: body.ip,
          userAgent: body.userAgent,
          purpose: TypeOfVerificationCode.LOGIN_2FA,
          metadata: { rememberMe: body.rememberMe, initiatedFrom: 'login' }
        })

        if (res) {
          const sltCookieConfig = envConfig.cookie.sltToken
          res.cookie(sltCookieConfig.name, sltJwt, {
            path: sltCookieConfig.path,
            domain: sltCookieConfig.domain,
            maxAge: sltCookieConfig.maxAge,
            httpOnly: sltCookieConfig.httpOnly,
            secure: sltCookieConfig.secure,
            sameSite: sltCookieConfig.sameSite as 'lax' | 'strict' | 'none' | boolean
          })
          this.logger.debug(`[Login] SLT token cookie (${sltCookieConfig.name}) set for 2FA.`)
        } else {
          this.logger.warn('[Login] Response object (res) not available to set SLT cookie for 2FA.')
        }

        const message = await this.i18nService.translate('Auth.Login.2FARequired', {
          lang: I18nContext.current()?.lang
        })
        return {
          message,
          twoFactorMethod: user.twoFactorMethod
        }
      } else if (!device.isTrusted) {
        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.notes = 'Device verification OTP required: Device not trusted.'
        await this.auditLogService.record(auditLogEntry as AuditLogData)

        const sltJwt = await this.otpService.initiateOtpWithSltCookie({
          email: user.email,
          userId: user.id,
          deviceId: device.id,
          ipAddress: body.ip,
          userAgent: body.userAgent,
          purpose: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
          metadata: { rememberMe: body.rememberMe, initiatedFrom: 'login' }
        })

        if (res) {
          const sltCookieConfig = envConfig.cookie.sltToken
          res.cookie(sltCookieConfig.name, sltJwt, {
            path: sltCookieConfig.path,
            domain: sltCookieConfig.domain,
            maxAge: sltCookieConfig.maxAge,
            httpOnly: sltCookieConfig.httpOnly,
            secure: sltCookieConfig.secure,
            sameSite: sltCookieConfig.sameSite as 'lax' | 'strict' | 'none' | boolean
          })
          this.logger.debug(`[Login] SLT token cookie (${sltCookieConfig.name}) set for untrusted device OTP.`)
        } else {
          this.logger.warn('[Login] Response object (res) not available to set SLT cookie for untrusted device OTP.')
        }

        const message = await this.i18nService.translate('Auth.Login.DeviceVerificationOtpRequired', {
          lang: I18nContext.current()?.lang
        })
        return {
          message,
          twoFactorMethod: TwoFactorMethodType.OTP
        }
      }

      const sessionData: Record<string, string | number | boolean | undefined | null> = {
        userId: user.id,
        deviceId: device.id,
        ipAddress: body.ip,
        userAgent: body.userAgent,
        createdAt: now.toISOString(),
        lastActiveAt: now.toISOString(),
        isTrusted: device.isTrusted,
        rememberMe: body.rememberMe,
        roleId: user.roleId,
        roleName: user.role.name,
        geoCountry: geoLocation?.country,
        geoCity: geoLocation?.city
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
          this.prismaService,
          body.rememberMe
        )

      sessionData.currentAccessTokenJti = accessTokenJti
      sessionData.currentRefreshTokenJti = refreshTokenJti
      const decodedToken = this.jwtService.decode(accessToken)
      sessionData.accessTokenExp = decodedToken.exp

      let absoluteSessionLifetimeMs = envConfig.ABSOLUTE_SESSION_LIFETIME_MS
      if (isNaN(absoluteSessionLifetimeMs)) {
        this.logger.warn(
          `[AuthenticationService.login] Invalid ABSOLUTE_SESSION_LIFETIME_MS detected (NaN): ${envConfig.ABSOLUTE_SESSION_LIFETIME}. Falling back to 30 days.`
        )
        absoluteSessionLifetimeMs = ms('30d')
      }
      sessionData.maxLifetimeExpiresAt = new Date(Date.now() + absoluteSessionLifetimeMs).toISOString()

      const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${user.id}`
      const refreshTokenJtiToSessionKey = `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${refreshTokenJti}`

      const absoluteSessionLifetimeSeconds = Math.floor(absoluteSessionLifetimeMs / 1000)
      const refreshTokenTTL = maxAgeForRefreshTokenCookie
        ? Math.floor(maxAgeForRefreshTokenCookie / 1000)
        : absoluteSessionLifetimeSeconds

      this.logger.debug(
        `[AuthenticationService.login] Preparing Redis pipeline for session ${sessionId}. ` +
          `sessionKey TTL: ${absoluteSessionLifetimeSeconds}, refreshTokenJtiToSessionKey TTL: ${refreshTokenTTL}`
      )

      await this.redisService.pipeline((pipeline) => {
        pipeline.hmset(sessionKey, sessionData as Record<string, string>)
        pipeline.expire(sessionKey, absoluteSessionLifetimeSeconds)
        pipeline.sadd(userSessionsKey, sessionId)
        pipeline.sadd(`${REDIS_KEY_PREFIX.DEVICE_SESSIONS}${device.id}`, sessionId)
        pipeline.set(refreshTokenJtiToSessionKey, sessionId, 'EX', refreshTokenTTL)
        return pipeline
      })

      if (res) {
        this.tokenService.setTokenCookies(res, accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie)
      } else {
        this.logger.warn(
          '[DEBUG AuthenticationService login - Direct login] Response object (res) is NOT present. Cookies will not be set by login function directly.'
        )
      }

      if (device.isTrusted && geoLocation && geoLocation.country && geoLocation.city) {
        const knownLocationsKey = `${REDIS_KEY_PREFIX.USER_KNOWN_LOCATIONS}${user.id}`
        const locationString = `${geoLocation.city?.toLowerCase()}_${geoLocation.country?.toLowerCase()}`

        this.logger.debug(`Attempting to SADD location: ${locationString} to key: ${knownLocationsKey}`)
        const isNewLocation = await this.redisService.sadd(knownLocationsKey, locationString)
        this.logger.debug(`SADD result for location ${locationString}: ${isNewLocation}`)

        if (isNewLocation === 1) {
          this.logger.warn(
            `New login location detected for user ${user.id} on trusted device ${device.id}: ${locationString}. Sending alert.`
          )
          auditLogEntry.notes = (
            (auditLogEntry.notes ? auditLogEntry.notes + '; ' : '') +
            `New trusted device login location: ${locationString}. Alert email sent.`
          ).trim()

          const i18nCtx = I18nContext.current()
          this.logger.debug('[AuthenticationService.login] I18nContext for new location email:', i18nCtx)
          const lang = i18nCtx?.lang || 'en'
          try {
            await this.emailService.sendSecurityAlertEmail({
              to: user.email,
              userName: user.name,
              alertSubject: this.i18nService.translate(
                'email.Email.SecurityAlert.Subject.NewTrustedDeviceLoginLocation',
                { lang }
              ),
              alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.NewTrustedDeviceLoginLocation', {
                lang
              }),
              mainMessage: this.i18nService.translate(
                'email.Email.SecurityAlert.MainMessage.NewTrustedDeviceLoginLocation',
                { lang }
              ),
              actionDetails: [
                {
                  label: this.i18nService.translate('email.Email.Field.Time', { lang }),
                  value: new Date().toLocaleString(lang)
                },
                {
                  label: this.i18nService.translate('email.Email.Field.IPAddress', { lang }),
                  value: body.ip
                },
                {
                  label: this.i18nService.translate('email.Email.Field.Device', { lang }),
                  value: body.userAgent
                },
                {
                  label: this.i18nService.translate('email.Email.Field.Location', { lang }),
                  value: `${geoLocation.city || 'N/A'}, ${geoLocation.country || 'N/A'}`
                }
              ],
              secondaryMessage: this.i18nService.translate('email.Email.SecurityAlert.SecondaryMessage.NotYou', {
                lang
              }),
              actionButtonText: this.i18nService.translate('email.Email.SecurityAlert.Button.SecureAccount', {
                lang
              }),
              actionButtonUrl: `${envConfig.FRONTEND_URL}/account/security`
            })
          } catch (emailError) {
            const errorMessage = emailError instanceof Error ? emailError.message : String(emailError)
            const errorStack = emailError instanceof Error ? emailError.stack : undefined
            this.logger.error(
              `Failed to send new trusted device login location alert to ${user.email}: ${errorMessage}`,
              errorStack
            )
          }
        }
      }

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'USER_LOGIN_SUCCESS'
      auditLogEntry.details.sessionId = sessionId

      if (user && device && sessionId && accessToken) {
        this.sessionManagementService
          .enforceSessionAndDeviceLimits(user.id, sessionId, device.id)
          .then((limitsResult) => {
            if (limitsResult.deviceLimitApplied || limitsResult.sessionLimitApplied) {
              this.logger.log(
                `Session/device limits applied for user ${user.id} after login. Devices removed: ${limitsResult.devicesRemovedCount}, Sessions revoked: ${limitsResult.sessionsRevokedCount}`
              )
            }
          })
          .catch((limitError) => {
            this.logger.error(
              `Error enforcing session/device limits for user ${user.id} after login: ${limitError.message}`,
              limitError.stack
            )
          })
      }

      return {
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role.name,
        isDeviceTrustedInSession: device.isTrusted,
        currentDeviceId: device.id,
        askToTrustDevice: shouldAskToTrustDevice
      }
    } catch (error) {
      this.logger.error('[AuthenticationService.login] Caught error:', error, typeof error)
      if (!auditLogEntry.errorMessage) {
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        } else if (error instanceof Error) {
          auditLogEntry.errorMessage = error.message
        } else if (typeof error === 'string') {
          auditLogEntry.errorMessage = error
        } else {
          try {
            auditLogEntry.errorMessage = JSON.stringify(error)
          } catch (stringifyError) {
            this.logger.error('[AuthenticationService.login] Failed to stringify caught error:', stringifyError)
            auditLogEntry.errorMessage = 'Unknown error during login (non-serializable error object)'
          }
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async logout(req: Request, res: Response) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'USER_LOGOUT_ATTEMPT',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      status: AuditLogStatus.FAILURE
    }

    const refreshTokenFromCookie = this.tokenService.extractRefreshTokenFromRequest(req)
    let activeUserFromToken: AccessTokenPayload | undefined = undefined

    try {
      const accessToken = this.tokenService.extractTokenFromHeader(req)
      if (accessToken) {
        try {
          activeUserFromToken = await this.tokenService.verifyAccessToken(accessToken)
          auditLogEntry.userId = activeUserFromToken.userId
          if (activeUserFromToken.sessionId) {
            auditLogEntry.details = {
              ...(auditLogEntry.details as object),
              sessionId: activeUserFromToken.sessionId
            } as Prisma.JsonObject
          }
        } catch (e) {
          this.logger.debug(
            'Could not decode or verify access token during logout. It might be expired or invalid. Will proceed if refresh token is present.'
          )
        }
      }

      if (!refreshTokenFromCookie) {
        this.logger.log('Logout called without refresh token cookie.')
        if (activeUserFromToken && activeUserFromToken.sessionId) {
          this.logger.log(
            `Invalidating session ${activeUserFromToken.sessionId} based on Access Token as Refresh Token cookie is missing.`
          )
          await this.tokenService.invalidateSession(activeUserFromToken.sessionId, 'USER_LOGOUT_NO_RT_COOKIE_WITH_AT')
          auditLogEntry.notes =
            'Logout processed: No refresh token cookie, session invalidated based on Access Token. Client cookies cleared.'
          auditLogEntry.details = {
            ...(auditLogEntry.details as object),
            sessionInvalidatedByAT: activeUserFromToken.sessionId
          } as Prisma.JsonObject
        } else {
          this.logger.log(
            'No refresh token cookie and no valid Access Token session to invalidate. Clearing only client-side cookies.'
          )
          auditLogEntry.notes = 'Logout processed: No refresh token cookie, no AT session. Client cookies cleared.'
        }

        this.tokenService.clearTokenCookies(res)
        const sltCookieConfig = envConfig.cookie.sltToken
        res.clearCookie(sltCookieConfig.name, { path: sltCookieConfig.path, domain: sltCookieConfig.domain })

        auditLogEntry.status = AuditLogStatus.SUCCESS
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        const message = await this.i18nService.translate('Auth.Logout.Processed', {
          lang: I18nContext.current()?.lang
        })
        return { message }
      }

      const sessionId = await this.tokenService.findSessionIdByRefreshTokenJti(refreshTokenFromCookie)
      if (sessionId) {
        auditLogEntry.details = {
          ...(auditLogEntry.details as object),
          sessionIdBeingLoggedOut: sessionId
        } as Prisma.JsonObject
        if (activeUserFromToken && activeUserFromToken.sessionId !== sessionId) {
          this.logger.warn(
            `Logout for session ${sessionId} initiated by user with active session ${activeUserFromToken.sessionId}. This is unusual for standard logout.`
          )
          auditLogEntry.notes = 'Logout for a session different from the active AT session.'
        }
        await this.tokenService.invalidateSession(sessionId, 'USER_LOGOUT')
        await this.tokenService.markRefreshTokenJtiAsUsed(refreshTokenFromCookie, sessionId)
      } else {
        await this.tokenService.markRefreshTokenJtiAsUsed(refreshTokenFromCookie, 'UNKNOWN_SESSION_ON_LOGOUT')
        this.logger.warn(
          `Session ID not found for refresh token JTI during logout. Refresh token JTI: ${refreshTokenFromCookie.substring(0, 10)}...`
        )
        auditLogEntry.notes = 'Session not found for refresh token, but RT JTI marked as used.'
      }

      this.tokenService.clearTokenCookies(res)

      const sltCookieConfig = envConfig.cookie.sltToken
      res.clearCookie(sltCookieConfig.name, { path: sltCookieConfig.path, domain: sltCookieConfig.domain })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'USER_LOGOUT_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      const message = await this.i18nService.translate('Auth.Logout.Success', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      const finalErrorAuditLog: AuditLogData = {
        action: auditLogEntry.action || 'USER_LOGOUT_EXCEPTION',
        status: AuditLogStatus.FAILURE,
        userId: auditLogEntry.userId,
        userEmail: auditLogEntry.userEmail,
        ipAddress: auditLogEntry.ipAddress || req?.ip,
        userAgent: auditLogEntry.userAgent || (req?.headers['user-agent'] as string),
        errorMessage: error instanceof Error ? error.message : String(error),
        details: (auditLogEntry.details || { errorType: error?.constructor?.name }) as Prisma.JsonObject,
        notes: auditLogEntry.notes || 'Exception during logout process',
        entity: auditLogEntry.entity,
        entityId: auditLogEntry.entityId,
        geoLocation: auditLogEntry.geoLocation as Prisma.JsonObject | undefined
      }

      await this.auditLogService.record(finalErrorAuditLog)

      this.logger.error(
        `Logout failed: ${finalErrorAuditLog.errorMessage}`,
        error instanceof Error ? error.stack : undefined,
        `Audit Details: ${JSON.stringify(finalErrorAuditLog.details)}`
      )

      this.tokenService.clearTokenCookies(res)
      const sltCookieConfigOnError = envConfig.cookie.sltToken
      res.clearCookie(sltCookieConfigOnError.name, {
        path: sltCookieConfigOnError.path,
        domain: sltCookieConfigOnError.domain
      })

      throw error
    }
  }

  async setRememberMe(
    activeUser: AccessTokenPayload,
    rememberMe: boolean,
    req: Request,
    res: Response,
    ip: string,
    userAgent: string
  ) {
    const currentRefreshTokenJti = this.tokenService.extractRefreshTokenFromRequest(req)
    if (!currentRefreshTokenJti) {
      this.logger.warn(
        `[AuthService setRememberMe] No refresh token JTI found in request for user ${activeUser.userId}`
      )

      throw MissingRefreshTokenException
    }

    const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${activeUser.sessionId}`
    const sessionDetails = await this.redisService.hgetall(sessionDetailsKey)

    if (Object.keys(sessionDetails).length === 0) {
      this.logger.warn(
        `[AuthService setRememberMe] Session details not found in Redis for session ${activeUser.sessionId}, user ${activeUser.userId}. Cannot update rememberMe.`
      )
      throw SessionNotFoundException
    }

    if (sessionDetails.currentRefreshTokenJti !== currentRefreshTokenJti) {
      this.logger.error(
        `[AuthService setRememberMe] CRITICAL: Mismatch between request RT JTI and session RT JTI for user ${activeUser.userId}, session ${activeUser.sessionId}. Request JTI: ${currentRefreshTokenJti}, Session JTI: ${sessionDetails.currentRefreshTokenJti}. Aborting rememberMe update and invalidating session.`
      )
      await this.tokenService.invalidateSession(activeUser.sessionId, 'RT_JTI_MISMATCH_ON_REMEMBER_ME')
      this.tokenService.clearTokenCookies(res)
      throw InvalidRefreshTokenException
    }

    const newMaxAgeForRefreshTokenCookie = rememberMe
      ? envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE
      : envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE

    this.tokenService.setTokenCookies(res, '', currentRefreshTokenJti, newMaxAgeForRefreshTokenCookie, true)

    await this.redisService.hset(sessionDetailsKey, 'rememberMe', rememberMe.toString())

    this.auditLogService.record({
      userId: activeUser.userId,
      action: 'REMEMBER_ME_UPDATED',
      status: AuditLogStatus.SUCCESS,
      entity: 'Session',
      entityId: activeUser.sessionId,
      ipAddress: ip,
      userAgent: userAgent,
      details: {
        rememberMe,
        oldMaxAge: sessionDetails.rememberMeMaxAge,
        newMaxAge: newMaxAgeForRefreshTokenCookie
      } as Prisma.JsonObject
    })

    const message = await this.i18nService.translate('Auth.RememberMe.Set', {
      lang: I18nContext.current()?.lang
    })
    return { message }
  }

  async completeLoginWithUntrustedDeviceOtp(
    body: TwoFactorVerifyBodyType & { userAgent: string; ip: string },
    sltContext: (SltContextData & { sltJti: string }) | null,
    res?: Response
  ) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'COMPLETE_LOGIN_UNTRUSTED_DEVICE_OTP_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        rememberMeRequested: body.rememberMe,
        codeProvided: !!body.code,
        sltContextProvided: !!sltContext,
        emailFromBody: body.email
      }
    }

    let effectiveEmail: string = ''
    let effectiveUserId: number

    try {
      if (!sltContext || !sltContext.sltJti) {
        auditLogEntry.errorMessage = 'SLT context or JTI is missing.'
        auditLogEntry.details.reason = 'MISSING_SLT_CONTEXT_OR_JTI'
        this.logger.error(
          '[AuthenticationService completeLoginWithUntrustedDeviceOtp] SLT context or JTI missing.',
          auditLogEntry.details
        )
        throw new ApiException(
          HttpStatus.INTERNAL_SERVER_ERROR,
          'SltProcessingError',
          'Error.Auth.Session.InvalidLogin'
        )
      }

      if (typeof sltContext.userId !== 'number') {
        auditLogEntry.errorMessage = 'User ID missing or invalid in SLT context.'
        auditLogEntry.details.reason = 'MISSING_OR_INVALID_USER_ID_IN_SLT'
        this.logger.error(auditLogEntry.errorMessage, sltContext)
        await this.otpService.finalizeSlt(sltContext.sltJti)
        throw new ApiException(
          HttpStatus.INTERNAL_SERVER_ERROR,
          'SltProcessingError',
          'Error.Auth.Session.InvalidLogin'
        )
      }
      effectiveUserId = sltContext.userId
      auditLogEntry.userId = effectiveUserId

      if (typeof sltContext.email === 'string' && sltContext.email.length > 0) {
        effectiveEmail = sltContext.email
      } else if (typeof body.email === 'string' && body.email.length > 0) {
        effectiveEmail = body.email
        this.logger.warn(
          `[AuthService completeLoginWithUntrustedDeviceOtp] SLT context for JTI ${sltContext.sltJti} is missing email. Using email from body: ${body.email}.`
        )
      } else {
        auditLogEntry.errorMessage = 'Email is required (missing in SLT context and body).'
        auditLogEntry.details.reason = 'MISSING_EMAIL_SLT_AND_BODY'
        this.logger.error(auditLogEntry.errorMessage, sltContext)
        await this.otpService.finalizeSlt(sltContext.sltJti)
        throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Email.NotFound', [
          { code: 'validation.email.required', path: 'email' }
        ])
      }
      auditLogEntry.userEmail = effectiveEmail

      auditLogEntry.details.sltJti = sltContext.sltJti
      auditLogEntry.details.sltPurpose = sltContext.purpose
      auditLogEntry.details.sltDeviceIdFromContext = sltContext.deviceId
      auditLogEntry.details.sltUserIdFromContext = sltContext.userId
      auditLogEntry.details.sltEmailFromContext = sltContext.email
      auditLogEntry.details.sltMetadata = sltContext.metadata as Prisma.JsonObject

      const currentAttempts = await this.otpService.getSltAttempts(sltContext.sltJti)
      auditLogEntry.details.currentSltAttempts = currentAttempts

      if (currentAttempts >= MAX_OTP_VERIFY_ATTEMPTS) {
        this.logger.warn(
          `[AuthService completeLoginWithUntrustedDeviceOtp] Max SLT verification attempts reached for JTI ${sltContext.sltJti}. Attempts: ${currentAttempts}`
        )
        await this.otpService.finalizeSlt(sltContext.sltJti)
        auditLogEntry.errorMessage = 'Max SLT verification attempts reached for untrusted device OTP.'
        auditLogEntry.details.reason = 'MAX_SLT_ATTEMPTS_REACHED_OTP'
        throw MaxVerificationAttemptsExceededException
      }

      const resultFromTransaction = await this.prismaService.$transaction(async (tx) => {
        const user = await this.sharedUserRepository.findUniqueWithRole({ id: effectiveUserId }, tx)

        if (!user || !user.role) {
          auditLogEntry.errorMessage = 'User or user role not found for untrusted device OTP login.'
          auditLogEntry.details.reason = 'USER_OR_ROLE_NOT_FOUND_OTP'
          throw EmailNotFoundException
        }
        auditLogEntry.userId = user.id
        auditLogEntry.userEmail = user.email

        if (typeof effectiveEmail !== 'string' || effectiveEmail.length === 0) {
          auditLogEntry.errorMessage = 'Effective email became invalid before OTP verification within transaction.'
          auditLogEntry.details.reason = 'EFFECTIVE_EMAIL_INVALID_IN_TX'
          this.logger.error(auditLogEntry.errorMessage, { currentEffectiveEmail: effectiveEmail })

          throw new ApiException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            'InternalServerError',
            'Error.Global.InternalServerError'
          )
        }

        if (sltContext.purpose !== TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP) {
          auditLogEntry.errorMessage = `Invalid SLT purpose: ${sltContext.purpose}. Expected LOGIN_UNTRUSTED_DEVICE_OTP.`
          auditLogEntry.details.reason = 'INVALID_SLT_PURPOSE_FOR_UNTRUSTED_OTP'
          await this.otpService.finalizeSlt(sltContext.sltJti)
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Otp.InvalidPurpose')
        }

        if (typeof body.code !== 'string' || body.code.length === 0) {
          auditLogEntry.errorMessage = 'OTP code is missing or invalid in the request body.'
          auditLogEntry.details.reason = 'INVALID_OTP_CODE_IN_BODY'

          throw InvalidOTPException
        }

        const isValidOtp = await this.otpService.verifyOtpOnly(
          effectiveEmail,
          body.code,
          TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
          user.id,
          body.ip,
          body.userAgent
        )

        if (!isValidOtp) {
          await this.otpService.incrementSltAttempts(sltContext.sltJti)
          auditLogEntry.details.sltAttemptIncremented = true
          const attemptsAfterIncrement = await this.otpService.getSltAttempts(sltContext.sltJti)
          auditLogEntry.details.sltAttemptsAfterIncrement = attemptsAfterIncrement
          auditLogEntry.errorMessage = 'Invalid OTP for untrusted device login.'

          if (attemptsAfterIncrement >= MAX_OTP_VERIFY_ATTEMPTS) {
            this.logger.warn(
              `[AuthService completeLoginWithUntrustedDeviceOtp] Max SLT attempts reached for JTI ${sltContext.sltJti} after failed OTP verification. Finalizing.`
            )
            await this.otpService.finalizeSlt(sltContext.sltJti)
            auditLogEntry.details.sltFinalizedAfterMaxAttemptsIncrement = true
            throw MaxVerificationAttemptsExceededException
          }
          throw InvalidOTPException
        }

        const deviceFromFindOrCreate = await this.deviceService.findOrCreateDevice(
          {
            userId: user.id,
            userAgent: sltContext.userAgent || body.userAgent,
            ip: sltContext.ipAddress || body.ip
          },
          tx
        )
        auditLogEntry.details.finalDeviceId = deviceFromFindOrCreate.id

        if (sltContext.deviceId && sltContext.deviceId !== deviceFromFindOrCreate.id) {
          auditLogEntry.errorMessage = `Device ID mismatch during untrusted device OTP login. SLT Device ID: ${sltContext.deviceId}, Identified Device ID: ${deviceFromFindOrCreate.id}.`
          auditLogEntry.details.reason = 'SLT_DEVICE_ID_MISMATCH_UNTRUSTED_OTP_LOGIN'
          this.logger.error(auditLogEntry.errorMessage)

          throw DeviceMismatchException
        }
        const device = deviceFromFindOrCreate

        let shouldRememberDevice = body.rememberMe
        if (shouldRememberDevice === undefined && sltContext?.metadata) {
          shouldRememberDevice = sltContext.metadata.rememberMe === true
        }
        shouldRememberDevice = shouldRememberDevice ?? false

        auditLogEntry.details.shouldRememberDevice = shouldRememberDevice
        auditLogEntry.details.initialDeviceIsTrusted = device.isTrusted

        if (shouldRememberDevice && !device.isTrusted) {
          await this.deviceService.trustDevice(device.id, user.id, tx)
          auditLogEntry.details.deviceTrustedInThisFlow = true
        }

        const { accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie, accessTokenPayload } =
          await this.tokenService.generateTokens(
            {
              userId: user.id,
              deviceId: device.id,
              roleId: user.role.id,
              roleName: user.role.name,
              sessionId: uuidv4(),
              isDeviceTrustedInSession: device.isTrusted || shouldRememberDevice
            },
            tx,
            shouldRememberDevice
          )

        await this.otpService.finalizeSlt(sltContext.sltJti)
        auditLogEntry.details.finalizedSltJtiOnSuccess = sltContext.sltJti

        if (res) {
          this.tokenService.setTokenCookies(res, accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie)
          this.tokenService.clearSltCookie(res)
        }

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'COMPLETE_LOGIN_UNTRUSTED_DEVICE_OTP_SUCCESS'
        auditLogEntry.details.finalSessionId = accessTokenPayload.sessionId
        auditLogEntry.details.isDeviceTrustedInSession = accessTokenPayload.isDeviceTrustedInSession

        return {
          userId: user.id,
          email: user.email,
          name: user.name,
          role: user.role.name,
          isDeviceTrustedInSession: accessTokenPayload.isDeviceTrustedInSession,
          currentDeviceId: device.id
        }
      })
      await this.auditLogService.recordAsync(auditLogEntry as AuditLogData)
      return resultFromTransaction
    } catch (error) {
      this.logger.error(
        `[AuthenticationService completeLoginWithUntrustedDeviceOtp] Failed for email ${effectiveEmail || auditLogEntry.userEmail || 'unknown'}: ${error.message}`,
        error.stack,
        auditLogEntry.details
      )

      if (sltContext?.sltJti) {
        this.logger.warn(
          `[AuthenticationService completeLoginWithUntrustedDeviceOtp] Caught error. SLT JTI ${sltContext.sltJti}. Error: ${error.message}. Ensure SLT is not prematurely finalized here.`
        )
      }

      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }

      this.auditLogService.recordAsync(auditLogEntry as AuditLogData)

      throw error
    }
  }

  async finalizeOauthLogin(
    user: User & { role: { id: number; name: string } },
    device: Device,
    rememberMe: boolean,
    ipAddress: string,
    userAgent: string,
    source: string = 'oauth-general',
    res?: Response
  ) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'USER_OAUTH_LOGIN_FINALIZE_ATTEMPT',
      userId: user.id,
      userEmail: user.email,
      ipAddress: ipAddress,
      userAgent: userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        source,
        rememberMeRequested: rememberMe,
        deviceId: device.id,
        isDeviceTrustedInitial: device.isTrusted
      }
    }

    try {
      const sessionId = uuidv4()
      const now = new Date()

      const geoLocation: GeolocationData | null = this.geolocationService.lookup(ipAddress)
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object' && geoLocation) {
        auditLogEntry.details.location = `${geoLocation.city || 'N/A'}, ${geoLocation.country || 'N/A'}`
      }

      const sessionData: Record<string, string | number | boolean | undefined | null> = {
        userId: user.id,
        deviceId: device.id,
        ipAddress: ipAddress,
        userAgent: userAgent,
        createdAt: now.toISOString(),
        lastActiveAt: now.toISOString(),
        isTrusted: device.isTrusted,
        rememberMe: rememberMe,
        roleId: user.role.id,
        roleName: user.role.name,
        geoCountry: geoLocation?.country,
        geoCity: geoLocation?.city,
        source: source
      }

      const { accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie, accessTokenJti } =
        await this.tokenService.generateTokens(
          {
            userId: user.id,
            deviceId: device.id,
            roleId: user.role.id,
            roleName: user.role.name,
            sessionId
          },
          this.prismaService,
          rememberMe
        )

      sessionData.currentAccessTokenJti = accessTokenJti
      sessionData.currentRefreshTokenJti = refreshTokenJti
      const decodedToken = this.jwtService.decode(accessToken)
      if (decodedToken && typeof decodedToken === 'object' && 'exp' in decodedToken) {
        sessionData.accessTokenExp = decodedToken.exp
      }

      let absoluteSessionLifetimeMs = envConfig.ABSOLUTE_SESSION_LIFETIME_MS
      if (isNaN(absoluteSessionLifetimeMs)) {
        this.logger.warn(
          `[AuthenticationService.finalizeOauthLogin] Invalid ABSOLUTE_SESSION_LIFETIME_MS: ${envConfig.ABSOLUTE_SESSION_LIFETIME_MS}. Falling back to 30 days.`
        )
        absoluteSessionLifetimeMs = ms('30d')
      }
      sessionData.maxLifetimeExpiresAt = new Date(Date.now() + absoluteSessionLifetimeMs).toISOString()

      const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${user.id}`
      const refreshTokenJtiToSessionKey = `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${refreshTokenJti}`

      const absoluteSessionLifetimeSeconds = Math.floor(absoluteSessionLifetimeMs / 1000)
      const refreshTokenTTL =
        maxAgeForRefreshTokenCookie && maxAgeForRefreshTokenCookie > 0
          ? Math.floor(maxAgeForRefreshTokenCookie / 1000)
          : absoluteSessionLifetimeSeconds

      await this.redisService.pipeline((pipeline) => {
        pipeline.hmset(sessionKey, sessionData as Record<string, string>)
        pipeline.expire(sessionKey, absoluteSessionLifetimeSeconds)
        pipeline.sadd(userSessionsKey, sessionId)
        pipeline.sadd(`${REDIS_KEY_PREFIX.DEVICE_SESSIONS}${device.id}`, sessionId)
        pipeline.set(refreshTokenJtiToSessionKey, sessionId, 'EX', refreshTokenTTL)
        return pipeline
      })

      if (res) {
        this.tokenService.setTokenCookies(res, accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie)
      } else {
        this.logger.warn(
          '[AuthenticationService.finalizeOauthLogin] Response object (res) is NOT present. Cookies will not be set by this function.'
        )
      }

      if (device.isTrusted && geoLocation && geoLocation.country && geoLocation.city) {
        const knownLocationsKey = `${REDIS_KEY_PREFIX.USER_KNOWN_LOCATIONS}${user.id}`
        const locationString = `${geoLocation.city?.toLowerCase()}_${geoLocation.country?.toLowerCase()}`
        const isNewLocation = await this.redisService.sadd(knownLocationsKey, locationString)
        if (isNewLocation === 1) {
          this.logger.warn(
            `New login location detected for user ${user.id} on trusted device ${device.id} via ${source}: ${locationString}. Sending alert.`
          )
          auditLogEntry.notes = (
            (auditLogEntry.notes ? auditLogEntry.notes + '; ' : '') +
            `New trusted device login location via ${source}: ${locationString}. Alert email sent.`
          ).trim()
          const lang = I18nContext.current()?.lang || 'en'
          try {
            await this.emailService.sendSecurityAlertEmail({
              to: user.email,
              userName: user.name || undefined,
              alertSubject: this.i18nService.translate(
                'email.Email.SecurityAlert.Subject.NewTrustedDeviceLoginLocation',
                { lang }
              ),
              alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.NewTrustedDeviceLoginLocation', {
                lang
              }),
              mainMessage: this.i18nService.translate(
                'email.Email.SecurityAlert.MainMessage.NewTrustedDeviceLoginLocation',
                { lang }
              ),
              actionDetails: [
                {
                  label: this.i18nService.translate('email.Email.Field.Time', { lang }),
                  value: new Date().toLocaleString(lang)
                },
                {
                  label: this.i18nService.translate('email.Email.Field.IPAddress', { lang }),
                  value: ipAddress
                },
                {
                  label: this.i18nService.translate('email.Email.Field.Device', { lang }),
                  value: userAgent
                },
                {
                  label: this.i18nService.translate('email.Email.Field.Location', { lang }),
                  value: `${geoLocation.city || 'N/A'}, ${geoLocation.country || 'N/A'}`
                }
              ],
              secondaryMessage: this.i18nService.translate('email.Email.SecurityAlert.SecondaryMessage.NotYou', {
                lang
              }),
              actionButtonText: this.i18nService.translate('email.Email.SecurityAlert.Button.SecureAccount', {
                lang
              }),
              actionButtonUrl: `${envConfig.FRONTEND_URL}/account/security`
            })
          } catch (emailError) {
            const errorMessage = emailError instanceof Error ? emailError.message : String(emailError)
            const errorStack = emailError instanceof Error ? emailError.stack : undefined
            this.logger.error(
              `Failed to send new trusted device login location alert (OAuth - ${source}) to ${user.email}: ${errorMessage}`,
              errorStack
            )
          }
        }
      }

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'USER_OAUTH_LOGIN_FINALIZE_SUCCESS'
      auditLogEntry.details.sessionId = sessionId
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      this.sessionManagementService
        .enforceSessionAndDeviceLimits(user.id, sessionId, device.id)
        .then((limitsResult) => {
          if (limitsResult.deviceLimitApplied || limitsResult.sessionLimitApplied) {
            this.logger.log(
              `Session/device limits applied for user ${user.id} after OAuth login. Devices removed: ${limitsResult.devicesRemovedCount}, Sessions revoked: ${limitsResult.sessionsRevokedCount}`
            )
          }
        })
        .catch((limitError) => {
          this.logger.error(
            `Error enforcing session/device limits for user ${user.id} after OAuth login: ${limitError.message}`,
            limitError.stack
          )
        })

      return {
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role.name,
        isDeviceTrustedInSession: device.isTrusted,
        currentDeviceId: device.id
      }
    } catch (error) {
      this.logger.error(
        `[AuthenticationService.finalizeOauthLogin] Error finalizing OAuth login for user ${user.email}:`,
        error
      )
      auditLogEntry.errorMessage = error instanceof Error ? error.message : String(error)
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async reverifyPassword(
    userId: number,
    sessionId: string,
    body: ReverifyPasswordBodyType,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ message: string }> {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'SESSION_REVERIFY_ATTEMPT',
      userId,
      ipAddress,
      userAgent,
      entity: 'Session',
      entityId: sessionId,
      status: AuditLogStatus.FAILURE,
      details: { verificationMethod: body.verificationMethod }
    }

    try {
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
        include: { RecoveryCode: true }
      })

      if (!user) {
        auditLogEntry.errorMessage = 'User not found during session reverification.'
        auditLogEntry.details.reason = 'USER_NOT_FOUND'
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }
      auditLogEntry.userEmail = user.email

      let verificationSuccess = false

      if (body.verificationMethod === 'password') {
        if (!body.password) {
          auditLogEntry.errorMessage = 'Password is required for password verification method.'
          auditLogEntry.details.reason = 'MISSING_PASSWORD_FIELD'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Password.Invalid')
        }
        const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
        if (!isPasswordMatch) {
          auditLogEntry.errorMessage = InvalidPasswordException.message
          auditLogEntry.details.reason = 'INVALID_PASSWORD'
          throw InvalidPasswordException
        }
        verificationSuccess = true
        auditLogEntry.details.passwordVerified = true
      } else if (body.verificationMethod === 'otp') {
        if (!body.otpCode) {
          auditLogEntry.errorMessage = 'OTP code is required for OTP verification method.'
          auditLogEntry.details.reason = 'MISSING_OTP_CODE_FIELD'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Otp.Invalid')
        }
        const isOtpValid = await this.otpService.verifyOtpOnly(
          user.email,
          body.otpCode,
          TypeOfVerificationCode.REVERIFY_SESSION_OTP,
          userId,
          ipAddress,
          userAgent
        )
        if (!isOtpValid) {
          auditLogEntry.errorMessage = 'Invalid OTP code for session reverification.'
          auditLogEntry.details.reason = 'INVALID_OTP_FOR_REVERIFICATION'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Otp.Invalid')
        }
        verificationSuccess = true
        auditLogEntry.details.otpVerified = true
      } else if (body.verificationMethod === 'totp') {
        if (!body.totpCode) {
          auditLogEntry.errorMessage = 'TOTP code is required for TOTP verification method.'
          auditLogEntry.details.reason = 'MISSING_TOTP_CODE_FIELD'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.2FA.InvalidTOTP')
        }
        if (!user.twoFactorEnabled || !user.twoFactorSecret || user.twoFactorMethod !== TwoFactorMethodType.TOTP) {
          auditLogEntry.errorMessage = 'TOTP verification not available or not configured for this user.'
          auditLogEntry.details.reason = 'TOTP_NOT_CONFIGURED'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'OperationNotAllowed', 'Error.Auth.2FA.NotEnabled')
        }
        const isTotpValid = this.twoFactorService.verifyTOTP({
          email: user.email,
          secret: user.twoFactorSecret,
          token: body.totpCode
        })
        if (!isTotpValid) {
          auditLogEntry.errorMessage = 'Invalid TOTP code for session reverification.'
          auditLogEntry.details.reason = 'INVALID_TOTP_FOR_REVERIFICATION'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.2FA.InvalidTOTP')
        }
        verificationSuccess = true
        auditLogEntry.details.totpVerified = true
      } else if (body.verificationMethod === 'recovery') {
        if (!body.recoveryCode) {
          auditLogEntry.errorMessage = 'Recovery code is required for recovery code verification method.'
          auditLogEntry.details.reason = 'MISSING_RECOVERY_CODE_FIELD'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.2FA.InvalidRecoveryCode')
        }
        if (!user.twoFactorEnabled) {
          auditLogEntry.errorMessage = 'Recovery code verification not available as 2FA is not enabled.'
          auditLogEntry.details.reason = 'RECOVERY_CODE_2FA_NOT_ENABLED'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'OperationNotAllowed', 'Error.Auth.2FA.NotEnabled')
        }
        await this.twoFactorService.verifyRecoveryCode(userId, body.recoveryCode, this.prismaService)
        verificationSuccess = true
        auditLogEntry.details.recoveryCodeVerified = true
      } else {
        const exhaustiveCheck: never = body
        auditLogEntry.errorMessage = 'Invalid verification method specified.'
        auditLogEntry.details.reason = 'INVALID_VERIFICATION_METHOD_UNREACHABLE'
        throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Global.ValidationFailed')
      }

      if (verificationSuccess) {
        const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
        const removedCount = await this.redisService.hdel(sessionDetailsKey, 'requiresPasswordReverification')

        if (removedCount > 0) {
          this.logger.log(`Session ${sessionId} reverified via ${body.verificationMethod}, flag removed from Redis.`)
          auditLogEntry.details.reverificationFlagRemoved = true
        } else {
          this.logger.warn(
            `Session ${sessionId} reverified via ${body.verificationMethod}, but reverification flag was not found or not removed from Redis.`
          )
          auditLogEntry.details.reverificationFlagRemoved = false
          auditLogEntry.notes = 'Reverification flag was not present in session details in Redis.'
        }

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'SESSION_REVERIFY_SUCCESS'
        await this.auditLogService.record(auditLogEntry as AuditLogData)

        const message = await this.i18nService.translate('Auth.Session.ReverifiedSuccessfully', {
          lang: I18nContext.current()?.lang
        })
        return { message }
      } else {
        auditLogEntry.errorMessage = 'Verification failed due to an unknown reason after method selection.'
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }
    } catch (error) {
      this.logger.error(
        `Session reverification failed for user ${userId}, session ${sessionId} with method ${body.verificationMethod}:`,
        error
      )
      if (!auditLogEntry.errorMessage && error instanceof Error) {
        auditLogEntry.errorMessage = error.message
      }
      if (error instanceof ApiException && !auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async initiateSessionReverificationOtp(userId: number, userEmail: string, userName: string): Promise<void> {
    this.logger.log(
      `[AuthenticationService] Initiating session reverification OTP for user ${userId} (Email: ${userEmail}, Name: ${userName})`
    )

    try {
      await this.otpService.sendOTP(userEmail, TypeOfVerificationCode.REVERIFY_SESSION_OTP, userId)
      this.logger.log(`Successfully sent session reverification OTP to ${userEmail}`)

      await this.auditLogService.record({
        action: 'REVERIFICATION_OTP_SENT',
        userId,
        userEmail,
        status: AuditLogStatus.SUCCESS,
        details: { context: 'session_reverification', userNameAttempted: userName }
      })
    } catch (error) {
      this.logger.error(`[AuthenticationService] Failed to send session reverification OTP to ${userEmail}:`, error)
      await this.auditLogService.record({
        action: 'REVERIFICATION_OTP_SENT_FAILED',
        userId,
        userEmail,
        status: AuditLogStatus.FAILURE,
        errorMessage: error instanceof Error ? error.message : 'Unknown OTP send error',
        details: { context: 'session_reverification', userNameAttempted: userName }
      })
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'OTP_SEND_FAILED', 'Error.Auth.Otp.SendFailed')
    }
  }
}
