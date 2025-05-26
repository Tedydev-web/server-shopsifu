import { Injectable, HttpStatus } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { LoginBodyType, RegisterBodyType } from 'src/routes/auth/auth.model'
import { Response, Request } from 'express'
import {
  AbsoluteSessionLifetimeExceededException,
  DeviceMismatchException,
  DeviceSetupFailedException,
  EmailAlreadyExistsException,
  EmailNotFoundException,
  InvalidPasswordException
} from 'src/routes/auth/auth.error'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { isUniqueConstraintPrismaError } from 'src/shared/utils/type-guards.utils'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { Device } from '@prisma/client'
import { TypeOfVerificationCode, TwoFactorMethodType } from '../constants/auth.constants'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { Prisma } from '@prisma/client'
import { I18nContext } from 'nestjs-i18n'
import { v4 as uuidv4 } from 'uuid'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import envConfig from 'src/shared/config'
import ms from 'ms'
import { GeolocationData } from 'src/shared/services/geolocation.service'

@Injectable()
export class AuthenticationService extends BaseAuthService {
  async register(body: RegisterBodyType & { userAgent?: string; ip?: string }) {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Prisma.JsonObject } = {
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
        const verificationToken = await this.otpService.validateVerificationToken({
          token: body.otpToken,
          email: body.email,
          type: TypeOfVerificationCode.REGISTER,
          tokenType: 'OTP',
          tx
        })

        if (verificationToken.userId) {
          auditLogEntry.userId = verificationToken.userId
        }
        auditLogEntry.details.verificationTokenDeviceId = verificationToken.deviceId

        if (verificationToken.deviceId && body.userAgent && body.ip) {
          const isValidDevice = await this.deviceService.validateDevice(
            verificationToken.deviceId,
            body.userAgent,
            body.ip,
            tx
          )
          if (!isValidDevice) {
            auditLogEntry.errorMessage = DeviceMismatchException.message
            auditLogEntry.details.reason = 'DEVICE_MISMATCH_ON_REGISTER'
            auditLogEntry.details.validatedDeviceId = verificationToken.deviceId
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
            roleId: clientRoleId
          },
          tx
        )

        auditLogEntry.userId = createdUser.id
        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'USER_REGISTER_SUCCESS'
        auditLogEntry.details.roleIdAssigned = clientRoleId

        await this.otpService.deleteOtpToken(body.otpToken, tx)

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
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Prisma.JsonObject } = {
      action: 'USER_LOGIN_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        rememberMeRequested: body.rememberMe
      } as Prisma.JsonObject
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

        if (!this.deviceService.isSessionValid(device)) {
          this.logger.warn(
            `[SECURITY AuthenticationService login] Absolute session lifetime exceeded for user ${user.id}, device ${device.id}. Forcing re-login.`
          )
          auditLogEntry.errorMessage = AbsoluteSessionLifetimeExceededException.message
          auditLogEntry.details.reason = 'ABSOLUTE_SESSION_LIFETIME_EXCEEDED_LOGIN'
        auditLogEntry.notes = `All sessions for device ${device.id} should be invalidated due to absolute session lifetime exceeded during login.`
          throw AbsoluteSessionLifetimeExceededException
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
        const loginSessionToken = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
          return this.otpService.createOtpToken({
            email: user.email,
            type: TypeOfVerificationCode.LOGIN_2FA,
            userId: user.id,
            deviceId: device.id,
            metadata: {
              rememberMe: body.rememberMe,
              sessionId,
              ip: body.ip,
              userAgent: body.userAgent,
              geoCountry: geoLocation?.country,
              geoCity: geoLocation?.city
            },
            tx
          })
        })

          auditLogEntry.status = AuditLogStatus.SUCCESS
          auditLogEntry.notes = '2FA required: Device not trusted.'
          const message = await this.i18nService.translate('error.Auth.Login.2FARequired', {
            lang: I18nContext.current()?.lang
          })
          return {
            message,
            loginSessionToken: loginSessionToken,
            twoFactorMethod: user.twoFactorMethod
          }
      } else if (!device.isTrusted) {
          await this.otpService.sendOTP(user.email, TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP)
        const loginSessionToken = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
          return this.otpService.createOtpToken({
            email: user.email,
            type: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
            userId: user.id,
            deviceId: device.id,
            metadata: {
              rememberMe: body.rememberMe,
              sessionId,
              ip: body.ip,
              userAgent: body.userAgent,
              geoCountry: geoLocation?.country,
              geoCity: geoLocation?.city
            },
            tx
          })
        })

          auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.notes = 'Device verification OTP required: Device not trusted.'
          const message = await this.i18nService.translate('error.Auth.Login.DeviceVerificationOtpRequired', {
            lang: I18nContext.current()?.lang
          })
          return {
            message,
            loginSessionToken: loginSessionToken,
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
      sessionData.accessTokenExp = this.jwtService.decode(accessToken).exp

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
              ) as string,
              alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.NewTrustedDeviceLoginLocation', {
                lang
              }) as string,
              mainMessage: this.i18nService.translate(
                'email.Email.SecurityAlert.MainMessage.NewTrustedDeviceLoginLocation',
                { lang }
              ) as string,
              actionDetails: [
                {
                  label: this.i18nService.translate('email.Email.Field.Time', { lang }) as string,
                  value: new Date().toLocaleString(lang)
                },
                {
                  label: this.i18nService.translate('email.Email.Field.IPAddress', { lang }) as string,
                  value: body.ip
                },
                {
                  label: this.i18nService.translate('email.Email.Field.Device', { lang }) as string,
                  value: body.userAgent
                },
                {
                  label: this.i18nService.translate('email.Email.Field.Location', { lang }) as string,
                  value: `${geoLocation.city || 'N/A'}, ${geoLocation.country || 'N/A'}`
                }
              ],
              secondaryMessage: this.i18nService.translate('email.Email.SecurityAlert.SecondaryMessage.NotYou', {
                lang
              }) as string,
              actionButtonText: this.i18nService.translate('email.Email.SecurityAlert.Button.SecureAccount', {
                lang
              }) as string,
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
        return {
          userId: user.id,
          email: user.email,
          name: user.name,
          role: user.role.name,
        isDeviceTrustedInSession: device.isTrusted
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
    const accessToken = this.tokenService.extractTokenFromRequest(req)
    const refreshTokenJti = this.tokenService.extractRefreshTokenFromRequest(req)
    const auditLogEntry: AuditLogData = {
      action: 'USER_LOGOUT',
      status: AuditLogStatus.SUCCESS,
      details: {
        accessTokenProvided: !!accessToken,
        refreshTokenJtiProvided: !!refreshTokenJti
      } as Prisma.JsonObject
    }

    let sessionIdFromAccessToken: string | undefined = undefined

    try {
      if (accessToken) {
        const decoded = await this.tokenService.verifyAccessToken(accessToken).catch(() => null)
        if (decoded) {
          auditLogEntry.userId = decoded.userId
          sessionIdFromAccessToken = decoded.sessionId
          if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
            ;(auditLogEntry.details as Prisma.JsonObject).deviceId = decoded.deviceId
            ;(auditLogEntry.details as Prisma.JsonObject).sessionId = decoded.sessionId
            ;(auditLogEntry.details as Prisma.JsonObject).accessTokenJti = decoded.jti
          }
          await this.tokenService.invalidateAccessTokenJti(decoded.jti, decoded.exp)
        }
      }

      if (sessionIdFromAccessToken) {
        await this.tokenService.invalidateSession(sessionIdFromAccessToken, 'USER_LOGOUT')
        auditLogEntry.notes = `Session ${sessionIdFromAccessToken} invalidated via access token.`
      } else if (refreshTokenJti) {
        const sessionIdFromRefreshToken = await this.tokenService.findSessionIdByRefreshTokenJti(refreshTokenJti)
        if (sessionIdFromRefreshToken) {
          await this.tokenService.invalidateSession(sessionIdFromRefreshToken, 'USER_LOGOUT_WITH_REFRESH_TOKEN')
          auditLogEntry.notes = `Session ${sessionIdFromRefreshToken} invalidated via refresh token JTI ${refreshTokenJti}.`
          if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
            ;(auditLogEntry.details as Prisma.JsonObject).sessionIdFromRt = sessionIdFromRefreshToken
          }
        } else {
          await this.tokenService.invalidateRefreshTokenJti(refreshTokenJti, 'UNKNOWN_SESSION_FOR_RT_ON_LOGOUT')
          auditLogEntry.notes = `Refresh token JTI ${refreshTokenJti} blacklisted during logout as no active session found.`
        }
      } else {
        auditLogEntry.notes = 'No access token session or refresh token JTI provided during logout.'
      }

      this.tokenService.clearTokenCookies(res)
      await this.auditLogService.record(auditLogEntry)
      const message = await this.i18nService.translate('error.Auth.Logout.Success', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      this.tokenService.clearTokenCookies(res)
      auditLogEntry.errorMessage = error.message
      auditLogEntry.status = AuditLogStatus.FAILURE
      await this.auditLogService.record(auditLogEntry)
      const message = await this.i18nService.translate('error.Auth.Logout.Processed', {
        lang: I18nContext.current()?.lang
      })
      return { message }
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
    const auditLogEntry: AuditLogData = {
      action: 'SET_REMEMBER_ME',
      userId: activeUser.userId,
      ipAddress: ip,
      userAgent: userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        rememberMeValue: rememberMe,
        deviceId: activeUser.deviceId
      } as Prisma.JsonObject
    }

    try {
      const result = await this.prismaService.$transaction(async (_tx) => {
        const currentRefreshTokenJti = this.tokenService.extractRefreshTokenFromRequest(req)
        const accessToken = this.tokenService.extractTokenFromRequest(req)
        let currentSessionId = activeUser.sessionId

        if (!currentSessionId && accessToken) {
          try {
            const decoded = await this.tokenService.verifyAccessToken(accessToken)
            currentSessionId = decoded.sessionId
          } catch (_e) {
            this.logger.warn('Could not decode access token to get sessionId for setRememberMe')
            throw new ApiException(HttpStatus.BAD_REQUEST, 'MissingSessionId', 'Error.Auth.Session.MissingSessionId')
          }
        }

        if (!currentSessionId) {
          this.logger.error('Session ID is missing in setRememberMe. Cannot proceed.')
          throw new ApiException(HttpStatus.BAD_REQUEST, 'MissingSessionId', 'Error.Auth.Session.MissingSessionId')
        }

        if (currentRefreshTokenJti) {
          const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${currentSessionId}`
          const sessionDetails = await this.redisService.hgetall(sessionKey)

          if (sessionDetails && sessionDetails.currentRefreshTokenJti === currentRefreshTokenJti) {
            await this.tokenService.invalidateRefreshTokenJti(currentRefreshTokenJti, currentSessionId)
          }
        }

        const {
          accessToken: newAccessToken,
          refreshTokenJti: newRefreshTokenJti,
          maxAgeForRefreshTokenCookie,
          accessTokenJti: newAccessTokenJti
        } = await this.tokenService.generateTokens(
          {
            userId: activeUser.userId,
            deviceId: activeUser.deviceId,
            roleId: activeUser.roleId,
            roleName: activeUser.roleName,
            sessionId: currentSessionId
          },
          undefined,
          rememberMe
        )

        const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${currentSessionId}`
        await this.redisService.hset(sessionKey, {
          rememberMe: rememberMe.toString(),
          currentRefreshTokenJti: newRefreshTokenJti,
          currentAccessTokenJti: newAccessTokenJti,
          lastActiveAt: new Date().toISOString()
        })

        this.tokenService.setTokenCookies(res, newAccessToken, newRefreshTokenJti, maxAgeForRefreshTokenCookie)

        auditLogEntry.status = AuditLogStatus.SUCCESS
        const message = await this.i18nService.translate('error.Auth.RememberMe.Set', {
          lang: I18nContext.current()?.lang
        })
        return {
          success: true,
          message
        }
      })

      await this.auditLogService.record(auditLogEntry)
      return result
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      await this.auditLogService.record(auditLogEntry)
      throw error
    }
  }
}
