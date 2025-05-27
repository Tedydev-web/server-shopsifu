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

      // Lookup geolocation
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
        absoluteSessionLifetimeMs = ms('30d') // Fallback to a known good value
      }
      sessionData.maxLifetimeExpiresAt = new Date(Date.now() + absoluteSessionLifetimeMs).toISOString()

      const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
      const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${user.id}`
      const refreshTokenJtiToSessionKey = `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${refreshTokenJti}`

      const absoluteSessionLifetimeSeconds = Math.floor(ms(envConfig.ABSOLUTE_SESSION_LIFETIME_MS) / 1000)
      const refreshTokenTTL = maxAgeForRefreshTokenCookie
        ? Math.floor(maxAgeForRefreshTokenCookie / 1000)
        : absoluteSessionLifetimeSeconds

      await this.redisService.pipeline((pipeline) => {
        pipeline.hmset(sessionKey, sessionData as Record<string, string>)
        pipeline.expire(sessionKey, absoluteSessionLifetimeSeconds)
        pipeline.sadd(userSessionsKey, sessionId)
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

      // Send email if login from new location on a trusted device
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
              actionButtonUrl: `${envConfig.FRONTEND_HOST_URL}/account/security`
            })
          } catch (emailError) {
            const errorMessage = emailError instanceof Error ? emailError.message : String(emailError)
            const errorStack = emailError instanceof Error ? emailError.stack : undefined
            this.logger.error(
              `Failed to send new trusted device login location alert to ${user.email}: ${errorMessage}`,
              errorStack
            )
            // Do not let email failure block the login flow
          }
        }
      }

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'USER_LOGIN_SUCCESS'
      auditLogEntry.details.sessionId = sessionId

      // Enforce limits after successful login and session creation (only if not pending 2FA/OTP)
      // This means a full accessToken was generated and cookies were (potentially) set.
      if (user && device && sessionId && accessToken) {
        // Check accessToken as a proxy for full login
        this.sessionManagementService
          .enforceSessionAndDeviceLimits(user.id, sessionId, device.id)
          .then((limitsResult) => {
            if (limitsResult.deviceLimitApplied || limitsResult.sessionLimitApplied) {
              this.logger.log(
                `Session/device limits applied for user ${user.id} after login. Devices removed: ${limitsResult.devicesRemovedCount}, Sessions revoked: ${limitsResult.sessionsRevokedCount}`
              )
              // TODO: Consider if/how to notify client about auto-revocations.
              // For now, logging is sufficient. We might throw MaxSessionsReachedException / MaxDevicesReachedException here if limits were applied *before* this session was established.
              // However, since this is *after* the current session is established, it's more about cleanup.
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
      const accessToken = this.tokenService.extractTokenFromHeader(req) // Try to get AT for logging userId
      if (accessToken) {
        try {
          // Attempt to verify AT. Could be expired but still gives us payload for logging.
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
          // If AT is invalid/expired, we might not get activeUserFromToken.
          // We still want to proceed if a refresh token is available.
          // If AT is required for logout (strict check), this guard should be at controller level.
          // For now, we allow logout with just RT if AT fails verification here.
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

        this.tokenService.clearTokenCookies(res) // Clear any lingering http-only cookies
        const sltCookieConfig = envConfig.cookie.sltToken
        res.clearCookie(sltCookieConfig.name, { path: sltCookieConfig.path, domain: sltCookieConfig.domain })

        auditLogEntry.status = AuditLogStatus.SUCCESS
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        const message = await this.i18nService.translate('Auth.Logout.Processed', {
          lang: I18nContext.current()?.lang
        })
        return { message }
      }

      // Proceed with refresh token based logout if refreshTokenFromCookie exists
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
        await this.tokenService.markRefreshTokenJtiAsUsed(refreshTokenFromCookie, sessionId) // Mark as used after invalidating session
      } else {
        // If session not found by RT JTI, it might have been already invalidated or RT is stale.
        // Still proceed to mark RT JTI as used to prevent replay if it's a known JTI.
        // We don't have a session ID here, so pass a placeholder or handle it in markRefreshTokenJtiAsUsed
        await this.tokenService.markRefreshTokenJtiAsUsed(refreshTokenFromCookie, 'UNKNOWN_SESSION_ON_LOGOUT')
        this.logger.warn(
          `Session ID not found for refresh token JTI during logout. Refresh token JTI: ${refreshTokenFromCookie.substring(0, 10)}...`
        )
        auditLogEntry.notes = 'Session not found for refresh token, but RT JTI marked as used.'
      }

      this.tokenService.clearTokenCookies(res)
      // Clear SLT cookie as well, if it exists, during logout
      const sltCookieConfig = envConfig.cookie.sltToken
      res.clearCookie(sltCookieConfig.name, { path: sltCookieConfig.path, domain: sltCookieConfig.domain })

      auditLogEntry.status = AuditLogStatus.SUCCESS // Set success before final record if all goes well
      auditLogEntry.action = 'USER_LOGOUT_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      const message = await this.i18nService.translate('Auth.Logout.Success', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      // Ensure all fields are set for the audit log in case of an error
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
      // Record the error audit log
      await this.auditLogService.record(finalErrorAuditLog)

      // Log the error with its own stack trace
      this.logger.error(
        `Logout failed: ${finalErrorAuditLog.errorMessage}`,
        error instanceof Error ? error.stack : undefined,
        `Audit Details: ${JSON.stringify(finalErrorAuditLog.details)}`
      )

      // Clear cookies as a safety measure even on error
      this.tokenService.clearTokenCookies(res)
      const sltCookieConfigOnError = envConfig.cookie.sltToken // Re-declare for scope
      res.clearCookie(sltCookieConfigOnError.name, {
        path: sltCookieConfigOnError.path,
        domain: sltCookieConfigOnError.domain
      })

      // Re-throw the original error or a generic one
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
      // This should ideally not happen if the user is authenticated with a valid RT
      throw MissingRefreshTokenException
    }

    const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${activeUser.sessionId}`
    const sessionDetails = await this.redisService.hgetall(sessionDetailsKey)

    if (Object.keys(sessionDetails).length === 0) {
      this.logger.warn(
        `[AuthService setRememberMe] Session details not found in Redis for session ${activeUser.sessionId}, user ${activeUser.userId}. Cannot update rememberMe.`
      )
      throw SessionNotFoundException // Or a more specific error
    }

    if (sessionDetails.currentRefreshTokenJti !== currentRefreshTokenJti) {
      this.logger.error(
        `[AuthService setRememberMe] CRITICAL: Mismatch between request RT JTI and session RT JTI for user ${activeUser.userId}, session ${activeUser.sessionId}. Request JTI: ${currentRefreshTokenJti}, Session JTI: ${sessionDetails.currentRefreshTokenJti}. Aborting rememberMe update and invalidating session.`
      )
      await this.tokenService.invalidateSession(activeUser.sessionId, 'RT_JTI_MISMATCH_ON_REMEMBER_ME')
      this.tokenService.clearTokenCookies(res)
      throw InvalidRefreshTokenException // Or a more specific critical error
    }

    const newMaxAgeForRefreshTokenCookie = rememberMe
      ? envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE
      : envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE

    // Update the cookie with the new maxAge
    this.tokenService.setTokenCookies(res, '', currentRefreshTokenJti, newMaxAgeForRefreshTokenCookie, true)

    // Update session details in Redis if necessary (e.g., if you store 'rememberMe' status in session)
    await this.redisService.hset(sessionDetailsKey, 'rememberMe', rememberMe.toString())
    // Also update the expiry of the session:details key itself if it should align with rememberMe
    // For now, session:details TTL is managed by absolute session lifetime

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
      } as Prisma.JsonObject // Assuming you might store oldMaxAge
    })

    const message = await this.i18nService.translate('error.Auth.RememberMe.Set', {
      lang: I18nContext.current()?.lang
    })
    return { message }
  }

  async completeLoginWithUntrustedDeviceOtp(
    body: TwoFactorVerifyBodyType & { userAgent: string; ip: string; sltCookie?: string },
    res?: Response
  ) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'LOGIN_UNTRUSTED_DEVICE_OTP_VERIFY_ATTEMPT',
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        sltCookieProvided: !!body.sltCookie,
        codeProvided: !!body.code,
        rememberMeFromClient: body.rememberMe
      }
    }

    if (!body.sltCookie) {
      auditLogEntry.errorMessage = 'Missing SLT cookie for untrusted device OTP login.'
      auditLogEntry.details.reason = 'MISSING_SLT_COOKIE'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.OtpToken.Invalid')
    }

    try {
      const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
        body.sltCookie,
        body.ip,
        body.userAgent,
        TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP
      )

      auditLogEntry.userId = sltContext.userId
      auditLogEntry.userEmail = sltContext.email
      auditLogEntry.details.sltJti = sltContext.sltJti
      auditLogEntry.details.sltPurpose = sltContext.purpose
      auditLogEntry.details.sltDeviceId = sltContext.deviceId
      auditLogEntry.details.sltRememberMe = sltContext.metadata?.rememberMe

      if (!sltContext.email || !sltContext.userId || !sltContext.deviceId) {
        auditLogEntry.errorMessage = 'Invalid SLT context data (missing email, userId, or deviceId).'
        auditLogEntry.details.reason = 'INVALID_SLT_CONTEXT_DATA'
        await this.otpService.finalizeSlt(sltContext.sltJti) // Finalize invalid context
        if (res) this.tokenService.clearSltCookie(res)
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }

      if (!body.code) {
        auditLogEntry.errorMessage = 'OTP code is missing.'
        auditLogEntry.details.reason = 'MISSING_OTP_CODE'
        // Do not finalize SLT here as user might retry with code
        throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Otp.Invalid')
      }

      await this.otpService.verifyOtpOnly(
        sltContext.email,
        body.code,
        TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
        sltContext.userId,
        body.ip,
        body.userAgent
      )
      auditLogEntry.details.otpVerified = true

      // IMPORTANT: Device should NOT be trusted automatically here.
      // Fetch the device record without trusting it.
      const deviceRecord = await this.deviceService.findDeviceById(sltContext.deviceId)
      if (!deviceRecord) {
        this.logger.error(
          `Device record not found (ID: ${sltContext.deviceId}) during OTP completion for user ${sltContext.userId}. This should not happen.`
        )
        throw DeviceSetupFailedException // Using existing exception
      }
      // auditLogEntry.details.deviceNowTrusted = false; // Explicitly log that it's not auto-trusted

      // Finalize the SLT context as it has been successfully used
      await this.otpService.finalizeSlt(sltContext.sltJti)
      if (res) {
        this.tokenService.clearSltCookie(res)
      }

      const user = await this.sharedUserRepository.findUniqueWithRole({ id: sltContext.userId })
      if (!user) {
        auditLogEntry.errorMessage = `User not found (ID: ${sltContext.userId}) after OTP verification.`
        auditLogEntry.details.reason = 'USER_NOT_FOUND_POST_OTP_VERIFY'
        throw EmailNotFoundException // Or a more generic server error
      }

      const sessionId = uuidv4()
      const now = new Date()
      const rememberMe = sltContext.metadata?.rememberMe === true || body.rememberMe === true
      auditLogEntry.details.finalRememberMe = rememberMe

      const geoLocation: GeolocationData | null = this.geolocationService.lookup(body.ip)
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object' && geoLocation) {
        auditLogEntry.details.location = `${geoLocation.city || 'N/A'}, ${geoLocation.country || 'N/A'}`
      }

      const sessionData: Record<string, string | number | boolean | undefined | null> = {
        userId: user.id,
        deviceId: deviceRecord.id,
        ipAddress: body.ip,
        userAgent: body.userAgent,
        createdAt: now.toISOString(),
        lastActiveAt: now.toISOString(),
        isTrusted: deviceRecord.isTrusted,
        rememberMe: rememberMe,
        roleId: user.role.id,
        roleName: user.role.name,
        geoCountry: geoLocation?.country,
        geoCity: geoLocation?.city
      }

      const { accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie, accessTokenJti } =
        await this.tokenService.generateTokens(
          {
            userId: user.id,
            deviceId: deviceRecord.id,
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
          `[AuthenticationService.completeLoginWithUntrustedDeviceOtp] Invalid ABSOLUTE_SESSION_LIFETIME_MS: ${envConfig.ABSOLUTE_SESSION_LIFETIME_MS}. Falling back to 30 days.`
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
        pipeline.set(refreshTokenJtiToSessionKey, sessionId, 'EX', refreshTokenTTL)
        return pipeline
      })

      if (res) {
        this.tokenService.setTokenCookies(res, accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie)
      } else {
        this.logger.warn(
          '[AuthenticationService.completeLoginWithUntrustedDeviceOtp] Response object (res) is NOT present. Cookies will not be set.'
        )
      }

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'LOGIN_UNTRUSTED_DEVICE_OTP_VERIFY_SUCCESS'
      auditLogEntry.details.sessionId = sessionId
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      this.sessionManagementService
        .enforceSessionAndDeviceLimits(user.id, sessionId, deviceRecord.id)
        .catch((limitError) => {
          this.logger.error(
            `Error enforcing session/device limits for user ${user.id} after untrusted device OTP login: ${limitError.message}`,
            limitError.stack
          )
        })

      return {
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role.name,
        isDeviceTrustedInSession: deviceRecord.isTrusted,
        currentDeviceId: deviceRecord.id
      }
    } catch (error) {
      this.logger.error(
        `[AuthenticationService.completeLoginWithUntrustedDeviceOtp] Error during OTP verification or login completion for user ${auditLogEntry.userEmail || 'unknown'}:`,
        error
      )
      if (!auditLogEntry.errorMessage) {
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        } else if (error instanceof Error) {
          auditLogEntry.errorMessage = error.message
        } else {
          auditLogEntry.errorMessage = 'Unknown error during untrusted device OTP login completion'
        }
      }
      // If SLT context might still be active due to an error before finalizeSlt was called
      if (body.sltCookie && !auditLogEntry.details.otpVerified) {
        try {
          const sltContextForCleanup = await this.otpService.validateSltFromCookieAndGetContext(
            body.sltCookie,
            body.ip,
            body.userAgent
            // No expected purpose, just get it for cleanup if it's still valid
          )
          if (sltContextForCleanup && sltContextForCleanup.sltJti) {
            await this.otpService.finalizeSlt(sltContextForCleanup.sltJti)
            this.logger.debug('SLT context finalized during error handling.')
            if (res) this.tokenService.clearSltCookie(res)
          }
        } catch (cleanupError) {
          this.logger.error('Error during SLT context cleanup in error handler:', cleanupError)
        }
      } else if (res && auditLogEntry.details.otpVerified === undefined) {
        // If OTP was not verified (or attempt didn't happen) AND SLT was provided, client might still have cookie
        // However, if OTP was verified and then something else failed, finalizeSlt + clearSltCookie should have run.
        // This is a safety net for cases where the error occurs before OTP verification logic, but after SLT validation attempt
        this.tokenService.clearSltCookie(res)
      }

      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
