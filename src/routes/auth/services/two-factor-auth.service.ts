import { Injectable, HttpStatus, Logger } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { v4 as uuidv4 } from 'uuid'
import { TokenType, TwoFactorMethodType, TypeOfVerificationCode } from '../constants/auth.constants'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { DisableTwoFactorBodyType, TwoFactorVerifyBodyType } from 'src/routes/auth/auth.model'
import {
  DeviceMismatchException,
  InvalidTOTPException,
  TOTPAlreadyEnabledException,
  TOTPNotEnabledException
} from 'src/routes/auth/auth.error'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { Response } from 'express'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { Prisma } from '@prisma/client'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import envConfig from 'src/shared/config'
import ms from 'ms'
import { SessionManagementService } from './session-management.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { HashingService } from 'src/shared/services/hashing.service'
import { RolesService } from '../roles.service'
import { AuthRepository } from '../auth.repo'
import { SharedUserRepository } from '../repositories/shared-user.repo'
import { EmailService } from '../providers/email.service'
import { TokenService } from '../providers/token.service'
import { TwoFactorService } from '../providers/2fa.service'
import { AuditLogService as AuditLogServiceType } from 'src/routes/audit-log/audit-log.service'
import { OtpService } from '../providers/otp.service'
import { DeviceService } from '../providers/device.service'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { JwtService } from '@nestjs/jwt'

@Injectable()
export class TwoFactorAuthService extends BaseAuthService {
  private readonly logger = new Logger(TwoFactorAuthService.name)

  constructor(
    prismaService: PrismaService,
    hashingService: HashingService,
    rolesService: RolesService,
    authRepository: AuthRepository,
    sharedUserRepository: SharedUserRepository,
    emailService: EmailService,
    tokenService: TokenService,
    twoFactorService: TwoFactorService,
    auditLogService: AuditLogServiceType,
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

  async setupTwoFactorAuth(userId: number) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'SETUP_2FA_ATTEMPT',
      userId,
      status: AuditLogStatus.FAILURE,
      details: {} as Prisma.JsonObject
    }

    try {
      const user = await this.sharedUserRepository.findUnique({ id: userId })
      if (!user) {
        throw new ApiException(404, 'User not found', 'Auth.UserNotFound')
      }

      if (user.twoFactorEnabled && user.twoFactorSecret) {
        auditLogEntry.errorMessage = TOTPAlreadyEnabledException.message
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        throw TOTPAlreadyEnabledException
      }

      const { secret, uri } = this.twoFactorService.generateTOTPSecret(user.email)
      const setupToken = uuidv4()

      await this.prismaService.verificationToken.create({
        data: {
          token: setupToken,
          email: user.email,
          type: TypeOfVerificationCode.SETUP_2FA,
          tokenType: TokenType.SETUP_2FA_TOKEN,
          expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
          userId,
          metadata: JSON.stringify({ secret })
        }
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'SETUP_2FA_INITIATED'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return {
        secret,
        uri,
        setupToken
      }
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error.message
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async confirmTwoFactorSetup(userId: number, setupToken: string, totpCode: string) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'CONFIRM_2FA_SETUP_ATTEMPT',
      userId,
      status: AuditLogStatus.FAILURE,
      details: {} as Prisma.JsonObject
    }

    try {
      const setupVerification = await this.prismaService.verificationToken.findFirst({
        where: {
          token: setupToken,
          userId,
          type: TypeOfVerificationCode.SETUP_2FA,
          tokenType: TokenType.SETUP_2FA_TOKEN,
          expiresAt: { gt: new Date() }
        }
      })

      if (!setupVerification || !setupVerification.metadata) {
        throw new ApiException(400, 'Invalid or expired setup token', 'Auth.TwoFactor.InvalidSetupToken')
      }

      let secret: string
      try {
        const metadata = JSON.parse(setupVerification.metadata)
        secret = metadata.secret
        if (!secret) {
          throw new Error('Secret not found in token metadata')
        }
      } catch {
        throw new ApiException(400, 'Invalid setup token metadata', 'Auth.TwoFactor.InvalidSetupToken')
      }

      const isValid = this.twoFactorService.verifyTOTP({
        email: userId.toString(),
        secret,
        token: totpCode
      })

      if (!isValid) {
        auditLogEntry.errorMessage = InvalidTOTPException.message
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        throw InvalidTOTPException
      }

      const recoveryCodes = this.twoFactorService.generateRecoveryCodes()

      // Update user with 2FA settings
      await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        await tx.user.update({
          where: { id: userId },
          data: {
            twoFactorEnabled: true,
            twoFactorSecret: secret,
            twoFactorMethod: TwoFactorMethodType.TOTP
          }
        })

        // Save recovery codes
        await this.twoFactorService.saveRecoveryCodes(userId, recoveryCodes, tx)

        // Delete the setup token
        await tx.verificationToken.delete({
          where: { id: setupVerification.id }
        })
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = '2FA_CONFIRM_SUCCESS'
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        ;(auditLogEntry.details as Prisma.JsonObject).recoveryCodesGenerated = recoveryCodes.length
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      // Send security alert email
      const userForEmail = await this.sharedUserRepository.findUnique({ id: userId })
      if (userForEmail) {
        const lang = I18nContext.current()?.lang || 'en'
        try {
          await this.emailService.sendSecurityAlertEmail({
            to: userForEmail.email,
            userName: userForEmail.name,
            alertSubject: this.i18nService.translate('email.Email.SecurityAlert.Subject.TwoFactorEnabled', { lang }),
            alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.TwoFactorEnabled', { lang }),
            mainMessage: this.i18nService.translate('email.Email.SecurityAlert.MainMessage.TwoFactorEnabled', { lang }),
            actionDetails: [
              {
                label: this.i18nService.translate('email.Email.Field.Time', { lang }),
                value: new Date().toLocaleString(lang)
              }
              // IP and Device might not be directly available here unless passed down
            ],
            secondaryMessage: this.i18nService.translate(
              'email.Email.SecurityAlert.SecondaryMessage.2FA.NotYouEnable',
              { lang }
            )
            // No specific button for this alert, user is informed.
          })
        } catch (emailError) {
          this.logger.error(
            `Failed to send 2FA enabled security alert to ${userForEmail.email}: ${emailError.message}`,
            emailError.stack
          )
        }
      }

      const message = this.i18nService.translate('error.Auth.2FA.Confirm.Success', {
        lang: I18nContext.current()?.lang
      })
      return {
        message,
        recoveryCodes
      }
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error.message
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async disableTwoFactorAuth(data: DisableTwoFactorBodyType & { userId: number; userAgent?: string; ip?: string }) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'DISABLE_2FA_ATTEMPT',
      userId: data.userId,
      ipAddress: data.ip,
      userAgent: data.userAgent,
      status: AuditLogStatus.FAILURE,
      details: { type: data.type } as Prisma.JsonObject
    }

    try {
      const user = await this.sharedUserRepository.findUnique({ id: data.userId })
      if (!user) {
        throw new ApiException(404, 'User not found', 'Auth.UserNotFound')
      }

      if (!user.twoFactorEnabled || !user.twoFactorSecret) {
        auditLogEntry.errorMessage = TOTPNotEnabledException.message
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        throw TOTPNotEnabledException
      }

      let isValid = false
      if (data.type === TwoFactorMethodType.TOTP) {
        isValid = this.twoFactorService.verifyTOTP({
          email: user.email,
          secret: user.twoFactorSecret,
          token: data.code
        })
      } else if (data.type === TwoFactorMethodType.RECOVERY && data.code) {
        try {
          await this.twoFactorService.verifyRecoveryCode(data.userId, data.code)
          isValid = true
        } catch {
          isValid = false
        }
      }

      if (!isValid) {
        auditLogEntry.errorMessage = InvalidTOTPException.message
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        throw InvalidTOTPException
      }

      await this.twoFactorService.updateUserTwoFactorStatus(data.userId, {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorMethod: null
      })

      await this.twoFactorService.deleteAllRecoveryCodes(data.userId)

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = '2FA_DISABLE_SUCCESS'
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        ;(auditLogEntry.details as Prisma.JsonObject).verificationMethod = data.type
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      // Send security alert email
      const userForEmailDisable = await this.sharedUserRepository.findUnique({ id: data.userId })
      if (userForEmailDisable) {
        const lang = I18nContext.current()?.lang || 'en'
        try {
          await this.emailService.sendSecurityAlertEmail({
            to: userForEmailDisable.email,
            userName: userForEmailDisable.name,
            alertSubject: this.i18nService.translate('email.Email.SecurityAlert.Subject.TwoFactorDisabled', { lang }),
            alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.TwoFactorDisabled', { lang }),
            mainMessage: this.i18nService.translate('email.Email.SecurityAlert.MainMessage.TwoFactorDisabled', {
              lang
            }),
            actionDetails: [
              {
                label: this.i18nService.translate('email.Email.Field.Time', { lang }),
                value: new Date().toLocaleString(lang)
              },
              {
                label: this.i18nService.translate('email.Email.Field.IPAddress', { lang }),
                value: data.ip || 'N/A'
              }
            ],
            secondaryMessage: this.i18nService.translate(
              'email.Email.SecurityAlert.SecondaryMessage.2FA.NotYouDisable',
              { lang }
            ),
            actionButtonText: this.i18nService.translate('email.Email.SecurityAlert.Button.Enable2FA', { lang }),
            actionButtonUrl: `${envConfig.FRONTEND_HOST_URL}/account/security` // TODO: Update with actual URL
          })
        } catch (emailError) {
          this.logger.error(
            `Failed to send 2FA disabled security alert to ${userForEmailDisable.email}: ${emailError.message}`,
            emailError.stack
          )
        }
      }

      const message = this.i18nService.translate('error.Auth.2FA.Disabled', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error.message
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async verifyTwoFactor(body: TwoFactorVerifyBodyType & { userAgent: string; ip: string }, res?: Response) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'VERIFY_2FA_ATTEMPT',
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        type: body.type,
        loginSessionTokenProvided: !!body.loginSessionToken
      } as Prisma.JsonObject
    }

    try {
      const result = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        const sessionToken = await this.otpService.findVerificationToken(body.loginSessionToken, tx)
        if (!sessionToken || !sessionToken.userId || !sessionToken.deviceId) {
          throw new ApiException(400, 'Invalid login session token', 'Auth.TwoFactor.InvalidLoginSessionToken')
        }

        auditLogEntry.userId = sessionToken.userId
        auditLogEntry.userEmail = sessionToken.email
        if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
          ;(auditLogEntry.details as Prisma.JsonObject).deviceId = sessionToken.deviceId
        }

        const user = await tx.user.findUnique({
          where: { id: sessionToken.userId },
          include: { role: true }
        })

        if (!user) {
          throw new ApiException(404, 'User not found', 'Auth.UserNotFound')
        }

        const isLoginFor2FA = sessionToken.type === TypeOfVerificationCode.LOGIN_2FA
        const isLoginForUntrustedDevice = sessionToken.type === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP

        // Validate based on verification type
        if (isLoginFor2FA && user.twoFactorEnabled && user.twoFactorSecret) {
          let isValid = false

          if (body.type === TwoFactorMethodType.TOTP) {
            isValid = this.twoFactorService.verifyTOTP({
              email: user.email,
              secret: user.twoFactorSecret,
              token: body.code
            })
          } else if (body.type === TwoFactorMethodType.RECOVERY && body.code) {
            try {
              await this.twoFactorService.verifyRecoveryCode(user.id, body.code, tx)
              isValid = true
            } catch {
              isValid = false
            }
          }

          if (!isValid) {
            auditLogEntry.errorMessage = InvalidTOTPException.message
            throw InvalidTOTPException
          }
        } else if (isLoginForUntrustedDevice && body.type === TwoFactorMethodType.OTP) {
          await this.otpService.validateVerificationCode({
            email: user.email,
            code: body.code,
            type: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
            tx
          })
        } else {
          throw new ApiException(400, 'Invalid verification method', 'Auth.TwoFactor.InvalidVerificationMethod')
        }

        // Check if device is valid
        const device = await tx.device.findUnique({
          where: { id: sessionToken.deviceId }
        })

        if (!device || device.userId !== user.id) {
          auditLogEntry.errorMessage = DeviceMismatchException.message
          throw DeviceMismatchException
        }

        // Extract rememberMe and sessionId from session token metadata
        let rememberMe = false
        let sessionIdFromToken: string | undefined = undefined
        let geoCountryFromToken: string | undefined = undefined
        let geoCityFromToken: string | undefined = undefined

        if (sessionToken.metadata) {
          try {
            const metadata = JSON.parse(sessionToken.metadata)
            rememberMe = !!metadata.rememberMe
            sessionIdFromToken = metadata.sessionId
            geoCountryFromToken = metadata.geoCountry
            geoCityFromToken = metadata.geoCity
          } catch (error) {
            this.logger.warn('Could not parse metadata for rememberMe/sessionId/geo preference', error)
          }
        }

        if (!sessionIdFromToken) {
          this.logger.error(
            'Session ID is missing in loginSessionToken metadata. Cannot proceed with 2FA verification.'
          )
          auditLogEntry.errorMessage = 'Missing sessionId in loginSessionToken metadata.'
          throw new ApiException(
            HttpStatus.BAD_REQUEST,
            'MissingSessionId',
            'Error.Auth.Session.MissingSessionIdInToken'
          )
        }

        const now = new Date()
        // Lookup geolocation if not found in token metadata
        let finalGeoCountry = geoCountryFromToken
        let finalGeoCity = geoCityFromToken

        if (!finalGeoCountry && body.ip) {
          const geoLocation = this.geolocationService.lookup(body.ip)
          if (geoLocation) {
            finalGeoCountry = geoLocation.country
            finalGeoCity = geoLocation.city
            if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
              ;(auditLogEntry.details as Prisma.JsonObject).location =
                `${finalGeoCity || 'N/A'}, ${finalGeoCountry || 'N/A'}`
            }
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
          rememberMe: rememberMe,
          roleId: user.roleId,
          roleName: user.role.name,
          geoCountry: finalGeoCountry,
          geoCity: finalGeoCity
        }

        // Generate tokens
        const { accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie, accessTokenJti } =
          await this.tokenService.generateTokens(
            {
              userId: user.id,
              deviceId: device.id,
              roleId: user.roleId,
              roleName: user.role.name,
              sessionId: sessionIdFromToken
            },
            tx,
            rememberMe
          )

        sessionData.currentAccessTokenJti = accessTokenJti
        sessionData.currentRefreshTokenJti = refreshTokenJti

        const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionIdFromToken}`
        const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${user.id}`
        const refreshTokenJtiToSessionKey = `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${refreshTokenJti}`

        const absoluteSessionLifetimeSeconds = Math.floor(ms(envConfig.ABSOLUTE_SESSION_LIFETIME_MS) / 1000)
        const refreshTokenTTL = maxAgeForRefreshTokenCookie
          ? Math.floor(maxAgeForRefreshTokenCookie / 1000)
          : absoluteSessionLifetimeSeconds

        await this.redisService.pipeline((pipeline) => {
          pipeline.hmset(sessionKey, sessionData as Record<string, string>)
          pipeline.expire(sessionKey, absoluteSessionLifetimeSeconds)
          pipeline.sadd(userSessionsKey, sessionIdFromToken)
          pipeline.set(refreshTokenJtiToSessionKey, sessionIdFromToken, 'EX', refreshTokenTTL)
          return pipeline
        })

        // Delete the session token from Prisma
        await this.otpService.deleteOtpToken(body.loginSessionToken, tx)

        if (res) {
          this.tokenService.setTokenCookies(res, accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie)
        }

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = '2FA_VERIFY_SUCCESS'
        if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
          ;(auditLogEntry.details as Prisma.JsonObject).verificationMethod = body.type
          ;(auditLogEntry.details as Prisma.JsonObject).rememberMe = rememberMe
        }

        // Send security alert email if this was a login for an untrusted device
        if (isLoginForUntrustedDevice) {
          const lang = I18nContext.current()?.lang || 'en'
          const locationInfo =
            finalGeoCity && finalGeoCountry ? `${finalGeoCity}, ${finalGeoCountry}` : body.ip || 'N/A'
          try {
            await this.emailService.sendSecurityAlertEmail({
              to: user.email,
              userName: user.name,
              alertSubject: this.i18nService.translate('email.Email.SecurityAlert.Subject.NewDeviceLogin', { lang }),
              alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.NewDeviceLogin', { lang }),
              mainMessage: this.i18nService.translate('email.Email.SecurityAlert.MainMessage.NewDeviceLogin', { lang }),
              actionDetails: [
                {
                  label: this.i18nService.translate('email.Email.Field.Time', { lang }),
                  value: new Date().toLocaleString(lang)
                },
                { label: this.i18nService.translate('email.Email.Field.IPAddress', { lang }), value: body.ip },
                {
                  label: this.i18nService.translate('email.Email.Field.Device', { lang }),
                  value: body.userAgent
                },
                {
                  label: this.i18nService.translate('email.Email.Field.Location', { lang }),
                  value: locationInfo
                }
              ],
              secondaryMessage: this.i18nService.translate('email.Email.SecurityAlert.SecondaryMessage.NotYou', {
                lang
              }),
              actionButtonText: this.i18nService.translate('email.Email.SecurityAlert.Button.SecureAccount', {
                lang
              }),
              // TODO: Update with actual URL to account security page
              actionButtonUrl: `${envConfig.FRONTEND_HOST_URL}/account/security`
            })
          } catch (emailError) {
            this.logger.error(`Failed to send new device login security alert to ${user.email}: ${emailError.message}`)
            // Do not let email failure block the login flow
          }
        }

        // Enforce session and device limits
        if (user && device && sessionIdFromToken) {
          this.sessionManagementService
            .enforceSessionAndDeviceLimits(user.id, sessionIdFromToken, device.id)
            .then((limitsResult) => {
              if (limitsResult.deviceLimitApplied || limitsResult.sessionLimitApplied) {
                this.logger.log(
                  `Session/device limits applied for user ${user.id} after 2FA verification. Devices removed: ${limitsResult.devicesRemovedCount}, Sessions revoked: ${limitsResult.sessionsRevokedCount}`
                )
              }
            })
            .catch((limitError) => {
              this.logger.error(
                `Error enforcing session/device limits for user ${user.id} after 2FA: ${limitError.message}`,
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
          currentDeviceId: device.id
        }
      })

      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error.message
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
