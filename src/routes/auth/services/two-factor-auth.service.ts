import { Injectable, HttpStatus, Logger } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { v4 as uuidv4 } from 'uuid'
import { TokenType, TwoFactorMethodType, TypeOfVerificationCode } from '../constants/auth.constants'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { DisableTwoFactorBodyType, TwoFactorVerifyBodyType } from 'src/routes/auth/auth.model'
import {
  DeviceMismatchException,
  InvalidCodeFormatException,
  InvalidRecoveryCodeException,
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
import { EmailNotFoundException, InvalidOTPTokenException, MismatchedSessionTokenException } from '../auth.error'
import { CookieNames } from 'src/shared/constants/auth.constant'

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
      const setupTokenKey = `${REDIS_KEY_PREFIX.TFA_SETUP_TOKEN}${setupToken}`
      const setupTokenTTLSeconds = 15 * 60 // 15 minutes

      // // Old DB storage:
      // await this.prismaService.verificationToken.create({
      //   data: {
      //     token: setupToken,
      //     email: user.email,
      //     type: TypeOfVerificationCode.SETUP_2FA,
      //     tokenType: TokenType.SETUP_2FA_TOKEN,
      //     expiresAt: new Date(Date.now() + setupTokenTTLSeconds * 1000),
      //     userId,
      //     metadata: JSON.stringify({ secret })
      //   }
      // })

      // New Redis storage:
      await this.redisService.set(
        setupTokenKey,
        JSON.stringify({ userId, secret, email: user.email }),
        'EX',
        setupTokenTTLSeconds
      )
      this.logger.debug(`2FA Setup token ${setupTokenKey} stored in Redis for user ${userId}`)

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'SETUP_2FA_INITIATED'
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        ;(auditLogEntry.details as Prisma.JsonObject).setupTokenKey = setupTokenKey
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return {
        secret,
        uri,
        setupToken // This token will be used by the client to confirm
      }
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error.message
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async confirmTwoFactorSetup(
    userId: number,
    setupToken: string,
    totpCode: string,
    // Optional: Pass these from controller if available, for more accurate logging
    requestIpAddress?: string,
    requestUserAgent?: string
  ) {
    const initialAuditDetails: Prisma.JsonObject = {
      userId,
      actionAttempted: 'CONFIRM_2FA_SETUP',
      setupTokenProvided: !!setupToken,
      totpCodeProvided: !!totpCode
    }
    if (requestIpAddress) initialAuditDetails.ipAddress = requestIpAddress
    if (requestUserAgent) initialAuditDetails.userAgent = requestUserAgent

    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: '2FA_CONFIRM_SETUP_ATTEMPT',
      userId: userId,
      ipAddress: requestIpAddress,
      userAgent: requestUserAgent,
      status: AuditLogStatus.FAILURE,
      details: initialAuditDetails
    }

    try {
      const resultFromTransaction = await this.prismaService.$transaction(async (tx) => {
        const user = await this.sharedUserRepository.findUniqueWithRole({ id: userId }, tx)
        if (!user) {
          auditLogEntry.errorMessage = 'User not found during 2FA confirmation.'
          auditLogEntry.details.reason = 'USER_NOT_FOUND'
          throw EmailNotFoundException
        }
        auditLogEntry.userEmail = user.email // For audit log enrichment

        if (user.twoFactorEnabled && user.twoFactorMethod === TwoFactorMethodType.TOTP) {
          auditLogEntry.errorMessage = '2FA (TOTP) is already enabled for this user.'
          auditLogEntry.details.reason = '2FA_ALREADY_ENABLED'
          throw TOTPAlreadyEnabledException
        }

        // Validate setup token
        const decodedSetupToken = await this.otpService.validateVerificationToken(
          setupToken,
          TypeOfVerificationCode.SETUP_2FA,
          user.email,
          undefined // deviceId not relevant
        )

        if (decodedSetupToken.userId !== userId || !decodedSetupToken.metadata?.twoFactorSecret) {
          auditLogEntry.errorMessage = 'Invalid or expired 2FA setup token, or secret missing.'
          auditLogEntry.details.reason = 'INVALID_SETUP_TOKEN_OR_SECRET_MISSING'
          throw InvalidOTPTokenException
        }
        const twoFactorSecretFromToken = decodedSetupToken.metadata.twoFactorSecret as string

        // Verify TOTP code against the secret from the setup token
        const isValidTOTP = this.twoFactorService.verifyTOTP({
          email: user.email, // or a unique identifier from user
          secret: twoFactorSecretFromToken,
          token: totpCode
        })

        if (!isValidTOTP) {
          auditLogEntry.errorMessage = 'Invalid TOTP code provided during 2FA setup confirmation.'
          auditLogEntry.details.reason = 'INVALID_TOTP_CODE'
          // Note: Not incrementing OTP failure here as it's a TOTP code
          throw InvalidTOTPException
        }

        // All checks passed, proceed to enable 2FA
        const recoveryCodes = this.twoFactorService.generateRecoveryCodes()
        await this.twoFactorService.saveRecoveryCodes(userId, recoveryCodes, tx)
        auditLogEntry.details.recoveryCodesGeneratedCount = recoveryCodes.length

        await this.authRepository.updateUser(
          { id: userId },
          {
            twoFactorEnabled: true,
            twoFactorSecret: twoFactorSecretFromToken, // Save the validated secret
            twoFactorMethod: TwoFactorMethodType.TOTP,
            twoFactorVerifiedAt: new Date() // Mark as verified
          },
          tx
        )

        // Invalidate the setup token as it's now used
        const nowForSetupTokenBlacklist = Math.floor(Date.now() / 1000)
        await this.otpService.blacklistVerificationToken(
          decodedSetupToken.jti,
          nowForSetupTokenBlacklist,
          decodedSetupToken.exp
        )
        auditLogEntry.details.setupTokenInvalidated = true

        // Since 2FA setup implies a new verified state, invalidate other sessions
        // to ensure they re-authenticate with 2FA if needed.
        await this.tokenService.invalidateAllUserSessions(userId, '2FA_SETUP_CONFIRMED')
        auditLogEntry.details.allOtherSessionsInvalidated = true

        // Create a new session for the user as 2FA setup is a form of re-authentication
        const device = await this.deviceService.findOrCreateDevice(
          {
            userId: user.id,
            userAgent: requestUserAgent || 'N/A',
            ip: requestIpAddress || 'N/A'
          },
          tx
        )
        auditLogEntry.details.finalDeviceId = device.id

        const newSessionId = uuidv4()
        // Enforce limits for this new session context
        await this.sessionManagementService.enforceSessionAndDeviceLimits(user.id, newSessionId, device.id)

        const { accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie, accessTokenJti } =
          await this.tokenService.generateTokens(
            {
              userId: user.id,
              deviceId: device.id,
              roleId: user.roleId,
              roleName: user.role.name,
              sessionId: newSessionId
            },
            tx,
            false // No rememberMe by default for 2FA setup confirmation
          )

        const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${newSessionId}`
        const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${user.id}`
        const absoluteSessionLifetimeSeconds = Math.floor(envConfig.ABSOLUTE_SESSION_LIFETIME_MS / 1000)

        const sessionData: Record<string, string | number | boolean> = {
          userId: user.id,
          deviceId: device.id,
          ipAddress: requestIpAddress || 'N/A',
          userAgent: requestUserAgent || 'N/A',
          createdAt: new Date().toISOString(),
          lastActiveAt: new Date().toISOString(),
          isTrusted: false, // Device is not trusted by default on 2FA setup confirmation
          rememberMe: false,
          roleId: user.roleId,
          roleName: user.role.name,
          currentAccessTokenJti: accessTokenJti,
          currentRefreshTokenJti: refreshTokenJti
        }

        const pipeline = this.redisService.client.pipeline()
        pipeline.hmset(sessionKey, sessionData)
        pipeline.expire(sessionKey, absoluteSessionLifetimeSeconds)
        pipeline.sadd(userSessionsKey, newSessionId)
        await pipeline.exec()

        auditLogEntry.details.newSessionIdCreated = newSessionId

        return {
          recoveryCodesToReturn: recoveryCodes,
          accessTokenToReturn: accessToken,
          refreshTokenJtiToReturn: refreshTokenJti,
          maxAgeForRefreshTokenCookieToReturn: maxAgeForRefreshTokenCookie,
          userForEmail: { id: user.id, email: user.email, name: user.name } // For email notification
        }
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = '2FA_CONFIRM_SETUP_SUCCESS'
      // finalAuditLogEntry.details will be merged from the one within transaction
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      // Send 2FA enabled notification email
      if (resultFromTransaction && resultFromTransaction.userForEmail) {
        const lang = I18nContext.current()?.lang || 'en'
        try {
          await this.emailService.sendSecurityAlertEmail({
            to: resultFromTransaction.userForEmail.email,
            userName: resultFromTransaction.userForEmail.name || undefined,
            alertSubject: this.i18nService.translate('email.Email.SecurityAlert.Subject.TwoFactorEnabled', { lang }),
            alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.TwoFactorEnabled', { lang }),
            mainMessage: this.i18nService.translate('email.Email.SecurityAlert.MainMessage.TwoFactorEnabled', {
              lang,
              args: { userName: resultFromTransaction.userForEmail.name }
            }),
            actionDetails: [
              {
                label: this.i18nService.translate('email.Email.Field.Time', { lang }),
                value: new Date().toLocaleString(lang)
              },
              {
                label: this.i18nService.translate('email.Email.Field.IPAddress', { lang }),
                value: requestIpAddress || 'N/A'
              },
              {
                label: this.i18nService.translate('email.Email.Field.Device', { lang }),
                value: requestUserAgent || 'N/A'
              }
            ],
            secondaryMessage: this.i18nService.translate(
              'email.Email.SecurityAlert.SecondaryMessage.2FA.NotYouEnable',
              {
                lang
              }
            ),
            actionButtonText: this.i18nService.translate('email.Email.SecurityAlert.Button.ReviewActivity', { lang }),
            actionButtonUrl: `${envConfig.FRONTEND_URL}/account/sessions`
          })
        } catch (emailError) {
          this.logger.error(
            `Failed to send 2FA enabled security alert to ${resultFromTransaction.userForEmail.email}: ${emailError.message}`,
            emailError.stack
          )
          // Do not let email failure block the main operation
        }
      }

      const message = await this.i18nService.translate('Auth.2FA.Confirm.Success', {
        lang: I18nContext.current()?.lang
      })

      return {
        message,
        recoveryCodes: resultFromTransaction.recoveryCodesToReturn
        // Optionally return tokens if the client should log in immediately
        // accessToken: resultFromTransaction.accessTokenToReturn,
        // refreshTokenJti: resultFromTransaction.refreshTokenJtiToReturn,
        // maxAgeForRefreshTokenCookie: resultFromTransaction.maxAgeForRefreshTokenCookieToReturn
      }
    } catch (error) {
      auditLogEntry.errorMessage = error instanceof Error ? error.message : String(error)
      if (error instanceof ApiException && error.details) {
        auditLogEntry.details.originalError = error.details as unknown as Prisma.JsonObject[]
      }
      // Ensure final logging attempt even on error
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      this.logger.error(
        `2FA setup confirmation failed for user ${userId}: ${error.message}`,
        error.stack,
        `Details: ${JSON.stringify(auditLogEntry.details)}`
      )
      throw error
    }
  }

  async disableTwoFactorAuth(data: DisableTwoFactorBodyType & { userId: number; userAgent?: string; ip?: string }) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: '2FA_DISABLE_ATTEMPT',
      userId: data.userId,
      ipAddress: data.ip,
      userAgent: data.userAgent,
      status: AuditLogStatus.FAILURE,
      details: { userId: data.userId } as Prisma.JsonObject
    }

    try {
      const resultFromTransaction = await this.prismaService.$transaction(async (tx) => {
        const user = await this.sharedUserRepository.findUniqueWithRole({ id: data.userId }, tx)
        if (!user || !user.twoFactorEnabled) {
          auditLogEntry.errorMessage = 'User not found or 2FA not enabled.'
          auditLogEntry.details.reason = 'USER_NOT_FOUND_OR_2FA_NOT_ENABLED'
          // Not throwing here yet, let audit log capture this state if transaction fails later
          throw TOTPNotEnabledException // Throw inside transaction to cause rollback
        }
        auditLogEntry.userEmail = user.email // For audit log enrichment

        let tokenVerified = false
        if (data.otpToken) {
          const verificationPayload = await this.otpService.validateVerificationToken(
            data.otpToken,
            TypeOfVerificationCode.DISABLE_2FA,
            user.email,
            undefined // deviceId is not relevant here
          )
          if (verificationPayload.userId !== user.id) {
            auditLogEntry.errorMessage = 'OTP token user ID mismatch.'
            auditLogEntry.details.reason = 'OTP_TOKEN_USER_ID_MISMATCH'
            throw InvalidOTPTokenException // Throw inside transaction
          }
          // Blacklist the token within the transaction
          const now = Math.floor(Date.now() / 1000)
          await this.otpService.blacklistVerificationToken(verificationPayload.jti, now, verificationPayload.exp)
          tokenVerified = true
          auditLogEntry.details.verificationMethod = 'OTP_TOKEN'
        } else if (data.totpCode) {
          if (!user.twoFactorSecret) {
            auditLogEntry.errorMessage = 'User 2FA secret not found for TOTP verification.'
            auditLogEntry.details.reason = 'USER_2FA_SECRET_NOT_FOUND'
            throw TOTPNotEnabledException // Throw inside transaction
          }
          const isValidTOTP = this.twoFactorService.verifyTOTP({
            email: user.email,
            secret: user.twoFactorSecret,
            token: data.totpCode
          })
          if (!isValidTOTP) {
            auditLogEntry.errorMessage = 'Invalid TOTP code provided.'
            auditLogEntry.details.reason = 'INVALID_TOTP_CODE'
            throw InvalidTOTPException // Throw inside transaction
          }
          tokenVerified = true
          auditLogEntry.details.verificationMethod = 'TOTP_CODE'
        }

        if (!tokenVerified) {
          auditLogEntry.errorMessage = 'No valid verification method provided (OTP token or TOTP code).'
          auditLogEntry.details.reason = 'NO_VALID_VERIFICATION_METHOD'
          throw InvalidCodeFormatException // Throw inside transaction
        }

        await this.authRepository.updateUser(
          { id: user.id },
          {
            twoFactorEnabled: false,
            twoFactorSecret: null,
            twoFactorMethod: null,
            twoFactorVerifiedAt: null,
            RecoveryCode: { deleteMany: {} } // Corrected relation name
          },
          tx
        )

        await this.tokenService.invalidateAllUserSessions(data.userId, '2FA_DISABLED')
        auditLogEntry.details.allOtherSessionsInvalidated = true

        return { userForEmail: { id: user.id, email: user.email, name: user.name } }
      })

      // If transaction is successful
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = '2FA_DISABLE_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      // Send email notification outside transaction
      if (resultFromTransaction && resultFromTransaction.userForEmail) {
        const lang = I18nContext.current()?.lang || 'en'
        try {
          await this.emailService.sendSecurityAlertEmail({
            to: resultFromTransaction.userForEmail.email,
            userName: resultFromTransaction.userForEmail.name || undefined,
            alertSubject: this.i18nService.translate('email.Email.SecurityAlert.Subject.TwoFactorDisabled', { lang }),
            alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.TwoFactorDisabled', { lang }),
            mainMessage: this.i18nService.translate('email.Email.SecurityAlert.MainMessage.TwoFactorDisabled', {
              lang,
              args: { userName: resultFromTransaction.userForEmail.name }
            }),
            actionDetails: [
              {
                label: this.i18nService.translate('email.Email.Field.Time', { lang }),
                value: new Date().toLocaleString(lang)
              },
              { label: this.i18nService.translate('email.Email.Field.IPAddress', { lang }), value: data.ip || 'N/A' },
              {
                label: this.i18nService.translate('email.Email.Field.Device', { lang }),
                value: data.userAgent || 'N/A'
              }
            ],
            secondaryMessage: this.i18nService.translate(
              'email.Email.SecurityAlert.SecondaryMessage.2FA.NotYouDisable',
              { lang }
            ),
            actionButtonText: this.i18nService.translate('email.Email.SecurityAlert.Button.Enable2FA', { lang }),
            actionButtonUrl: `${envConfig.FRONTEND_URL}/account/security`
          })
        } catch (emailError) {
          this.logger.error(
            `Failed to send 2FA disabled security alert to ${resultFromTransaction.userForEmail.email}: ${emailError.message}`,
            emailError.stack
          )
        }
      }
      const message = await this.i18nService.translate('Auth.2FA.Disabled', { lang: I18nContext.current()?.lang })
      return { message }
    } catch (error) {
      // Error might have occurred before or during transaction
      // auditLogEntry status is already FAILURE
      auditLogEntry.errorMessage = error instanceof Error ? error.message : String(error)
      if (error instanceof ApiException && error.details) {
        auditLogEntry.details.originalError = error.details as unknown as Prisma.JsonObject[]
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData) // Log failure
      this.logger.error(
        `2FA disable failed for user ${data.userId}: ${error.message}`,
        error.stack,
        `Details: ${JSON.stringify(auditLogEntry.details)}`
      )
      throw error // Re-throw original error
    }
  }

  async verifyTwoFactor(
    body: TwoFactorVerifyBodyType & { userAgent: string; ip: string; sltCookie?: string },
    res?: Response
  ) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: '2FA_VERIFY_ATTEMPT_WITH_SLT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        emailProvidedInBody: body.email,
        rememberMe: body.rememberMe,
        sltCookieProvided: !!body.sltCookie,
        bodyHasEmail: !!body.email
      } as Prisma.JsonObject
    }

    let sltContext: Awaited<ReturnType<typeof this.otpService.validateSltFromCookieAndGetContext>> | null = null
    let effectiveEmail: string | undefined = body.email
    let effectiveUserId: number | undefined = undefined

    try {
      if (body.sltCookie) {
        sltContext = await this.otpService.validateSltFromCookieAndGetContext(
          body.sltCookie,
          body.ip,
          body.userAgent
          // Không truyền expectedPurpose ở đây nữa, sẽ kiểm tra purpose từ sltContext sau
        )

        if (sltContext && sltContext.userId) {
          effectiveUserId = sltContext.userId
          auditLogEntry.userId = effectiveUserId
          auditLogEntry.details.sltJti = sltContext.sltJti
          auditLogEntry.details.sltPurpose = sltContext.purpose
          auditLogEntry.details.sltDeviceId = sltContext.deviceId
          auditLogEntry.details.userIdFromSlt = effectiveUserId
          auditLogEntry.details.sltMetadata = sltContext.metadata as Prisma.JsonObject // Log metadata từ SLT

          if (sltContext.email) {
            effectiveEmail = sltContext.email
            auditLogEntry.userEmail = effectiveEmail
            auditLogEntry.details.emailFromSlt = effectiveEmail
            if (body.email && body.email !== sltContext.email) {
              this.logger.warn(
                `Email mismatch: SLT context email ('${sltContext.email}') differs from body email ('${body.email}') for SLT JTI ${sltContext.sltJti}. Prioritizing SLT email.`
              )
              auditLogEntry.details.emailMismatchWarning = `SLT: ${sltContext.email}, Body: ${body.email}`
            }
          } else {
            this.logger.warn(
              `SLT context for JTI ${sltContext.sltJti} is missing email. Falling back to body email if present.`
            )
            if (!body.email) {
              auditLogEntry.errorMessage = 'Email is required (missing in SLT context and body).'
              auditLogEntry.details.reason = 'MISSING_EMAIL_SLT_AND_BODY'
              throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Email.NotFound', [
                { code: 'validation.email.required', path: 'email' }
              ])
            }
          }
        } else {
          auditLogEntry.errorMessage = 'Invalid or expired SLT context from cookie.'
          auditLogEntry.details.reason = 'INVALID_SLT_CONTEXT_FROM_COOKIE'
          throw MismatchedSessionTokenException
        }
      } else {
        auditLogEntry.details.sltCookieMissing = true
        if (!body.email) {
          auditLogEntry.errorMessage = 'Email is required (SLT cookie not provided).'
          auditLogEntry.details.reason = 'MISSING_EMAIL_NO_SLT'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Email.NotFound', [
            { code: 'validation.email.required', path: 'email' }
          ])
        }
        this.logger.warn('No SLT cookie provided for 2FA/OTP. Proceeding with email from body.')
      }

      if (!effectiveEmail) {
        auditLogEntry.errorMessage = 'Effective email could not be determined.'
        auditLogEntry.details.reason = 'EFFECTIVE_EMAIL_UNDETERMINED'
        throw EmailNotFoundException
      }

      const userLookupCriteria = effectiveUserId ? { id: effectiveUserId } : { email: effectiveEmail }

      const resultFromTransaction = await this.prismaService.$transaction(async (tx) => {
        const user = await this.sharedUserRepository.findUniqueWithRole(userLookupCriteria, tx)

        if (!user || !user.role) {
          auditLogEntry.errorMessage = 'User or user role not found.'
          auditLogEntry.details.reason = 'USER_OR_ROLE_NOT_FOUND'
          auditLogEntry.userEmail = effectiveEmail
          throw EmailNotFoundException
        }

        if (!effectiveUserId) {
          effectiveUserId = user.id
        }
        auditLogEntry.userId = effectiveUserId
        auditLogEntry.userEmail = user.email

        // --- Logic xác minh mã dựa trên sltPurpose và user.twoFactorMethod ---
        if (!sltContext || !sltContext.purpose) {
          auditLogEntry.errorMessage = 'SLT context or purpose is missing, cannot determine verification type.'
          auditLogEntry.details.reason = 'MISSING_SLT_CONTEXT_OR_PURPOSE'
          this.logger.error(auditLogEntry.errorMessage)
          throw new ApiException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            'SltProcessingError',
            'Error.Auth.Session.InvalidLogin'
          )
        }

        const { purpose: sltPurpose } = sltContext
        let isValidCode = false
        // let recoveryCodeUsed = false; // Biến này không còn được sử dụng trực tiếp

        if (sltPurpose === TypeOfVerificationCode.LOGIN_2FA) {
          if (!user.twoFactorEnabled || !user.twoFactorSecret || !user.twoFactorMethod) {
            auditLogEntry.errorMessage = 'User 2FA not configured (secret/method missing) for LOGIN_2FA purpose.'
            auditLogEntry.details.reason = 'USER_2FA_NOT_CONFIGURED_FOR_LOGIN_2FA'
            throw TOTPNotEnabledException
          }
          auditLogEntry.details.userTwoFactorMethod = user.twoFactorMethod

          if (body.recoveryCode) {
            if (
              user.twoFactorMethod !== TwoFactorMethodType.TOTP &&
              user.twoFactorMethod !== TwoFactorMethodType.RECOVERY
            ) {
              // Allow recovery for TOTP method as well.
              auditLogEntry.errorMessage = `Recovery code used with incompatible 2FA method (${user.twoFactorMethod}).`
              auditLogEntry.details.reason = 'RECOVERY_CODE_INVALID_METHOD'
              throw InvalidRecoveryCodeException
            }
            const recoveryCodeResult = await this.twoFactorService.verifyRecoveryCode(user.id, body.recoveryCode, tx)
            isValidCode = !!recoveryCodeResult
            if (isValidCode) {
              auditLogEntry.details.twoFactorMethodUsed = TwoFactorMethodType.RECOVERY
              // recoveryCodeUsed = true;
            } else {
              auditLogEntry.errorMessage = 'Invalid recovery code for LOGIN_2FA.'
              auditLogEntry.details.reason = 'INVALID_RECOVERY_CODE_FOR_2FA'
            }
          } else if (body.code) {
            if (user.twoFactorMethod === TwoFactorMethodType.TOTP) {
              isValidCode = this.twoFactorService.verifyTOTP({
                email: user.email,
                secret: user.twoFactorSecret,
                token: body.code
              })
              if (isValidCode) {
                auditLogEntry.details.twoFactorMethodUsed = TwoFactorMethodType.TOTP
              } else {
                auditLogEntry.errorMessage = 'Invalid TOTP code (from body.code) for LOGIN_2FA.'
                auditLogEntry.details.reason = 'INVALID_TOTP_CODE_FOR_2FA'
              }
            } else if (user.twoFactorMethod === TwoFactorMethodType.OTP) {
              const emailForOtpVerification = sltContext.email || effectiveEmail
              if (!emailForOtpVerification) {
                auditLogEntry.errorMessage = 'Email not found for OTP (2FA) verification.'
                auditLogEntry.details.reason = 'EMAIL_MISSING_FOR_2FA_OTP'
                throw EmailNotFoundException
              }
              try {
                isValidCode = await this.otpService.verifyOtpOnly(
                  emailForOtpVerification,
                  body.code,
                  TypeOfVerificationCode.LOGIN_2FA,
                  user.id,
                  body.ip,
                  body.userAgent
                )
                if (isValidCode) {
                  auditLogEntry.details.twoFactorMethodUsed = TwoFactorMethodType.OTP
                } else {
                  // verifyOtpOnly throws specific exceptions (InvalidOTPException, OTPExpiredException),
                  // so this 'else' block might not be reached if it throws.
                  // If it returns false without throwing, then this message is appropriate.
                  auditLogEntry.errorMessage = 'Invalid OTP (from body.code) for LOGIN_2FA (method OTP).'
                }
              } catch (otpError) {
                // Catch errors from verifyOtpOnly to set audit log and rethrow
                auditLogEntry.errorMessage = otpError instanceof Error ? otpError.message : String(otpError)
                auditLogEntry.details.otpVerificationError = otpError.constructor.name
                throw otpError // Rethrow to be caught by the outer try-catch
              }
            } else {
              auditLogEntry.errorMessage = `Unsupported 2FA method ('${user.twoFactorMethod}') for code verification.`
              auditLogEntry.details.reason = 'UNSUPPORTED_2FA_METHOD_FOR_CODE_VERIFY'
              throw InvalidTOTPException
            }
          } else {
            auditLogEntry.errorMessage = 'Neither code nor recovery code was provided for LOGIN_2FA purpose.'
            auditLogEntry.details.reason = 'NO_2FA_CODE_PROVIDED_FOR_2FA'
            throw InvalidCodeFormatException
          }
        } else if (sltPurpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP) {
          // Đây là trường hợp xác minh OTP cho thiết bị không tin cậy (không phải là 2FA chính thức của user)
          if (body.code) {
            const emailForOtpVerification = sltContext.email || effectiveEmail
            if (!emailForOtpVerification) {
              auditLogEntry.errorMessage = 'Email not found for OTP (untrusted device) verification.'
              auditLogEntry.details.reason = 'EMAIL_MISSING_FOR_UNTRUSTED_OTP'
              throw EmailNotFoundException
            }
            try {
              isValidCode = await this.otpService.verifyOtpOnly(
                emailForOtpVerification,
                body.code,
                TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
                user.id,
                body.ip,
                body.userAgent
              )
              if (isValidCode) {
                auditLogEntry.details.verificationMethod = 'OTP_UNTRUSTED_DEVICE'
              } else {
                auditLogEntry.errorMessage = 'Invalid OTP (from body.code) for LOGIN_UNTRUSTED_DEVICE_OTP.'
              }
            } catch (otpError) {
              auditLogEntry.errorMessage = otpError instanceof Error ? otpError.message : String(otpError)
              auditLogEntry.details.otpVerificationError = otpError.constructor.name
              throw otpError
            }
          } else {
            auditLogEntry.errorMessage = 'Code was not provided for LOGIN_UNTRUSTED_DEVICE_OTP purpose.'
            auditLogEntry.details.reason = 'NO_CODE_PROVIDED_FOR_UNTRUSTED_OTP'
            throw InvalidCodeFormatException
          }
        } else {
          auditLogEntry.errorMessage = `Unsupported SLT purpose for verification: ${sltPurpose}`
          auditLogEntry.details.reason = 'UNSUPPORTED_SLT_PURPOSE_FOR_VERIFICATION'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Session.InvalidLogin')
        }

        if (!isValidCode) {
          if (!auditLogEntry.errorMessage) {
            // Set a generic if not already set by specific logic
            auditLogEntry.errorMessage = 'Verification code is invalid.'
          }
          if (sltPurpose === TypeOfVerificationCode.LOGIN_2FA) {
            throw body.recoveryCode ? InvalidRecoveryCodeException : InvalidTOTPException
          } else if (sltPurpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP) {
            // InvalidOTPException should be thrown by verifyOtpOnly if it failed that way
            throw InvalidCodeFormatException // Fallback if verifyOtpOnly returned false without specific error
          }
          throw InvalidCodeFormatException
        }

        // Device handling:
        if (!sltContext.deviceId) {
          // Should always have deviceId from SLT context at this stage
          auditLogEntry.errorMessage = 'SLT Context is missing deviceId for 2FA/OTP completion.'
          auditLogEntry.details.reason = 'SLT_CONTEXT_MISSING_DEVICE_ID'
          throw new ApiException(
            HttpStatus.INTERNAL_SERVER_ERROR, // This is an internal logic error
            'SltProcessingError',
            'Error.Auth.Session.InvalidLogin'
          )
        }

        const deviceFromFindOrCreate = await this.deviceService.findOrCreateDevice(
          { userId: user.id, userAgent: sltContext.userAgent, ip: sltContext.ipAddress },
          tx
        )

        // Critical check for device ID consistency
        if (sltContext.deviceId !== deviceFromFindOrCreate.id) {
          auditLogEntry.errorMessage = `Device ID mismatch: SLT context device ID (${sltContext.deviceId}) differs from identified device ID (${deviceFromFindOrCreate.id}) for user ${user.id}.`
          auditLogEntry.details.sltDeviceId = sltContext.deviceId
          auditLogEntry.details.identifiedDeviceIdByService = deviceFromFindOrCreate.id
          auditLogEntry.details.reason = 'SLT_DEVICE_ID_MISMATCH_WITH_CURRENT_DEVICE_IDENTIFICATION'
          this.logger.error(
            auditLogEntry.errorMessage,
            `SLT UserAgent: ${sltContext.userAgent}, SLT IP: ${sltContext.ipAddress}`
          )
          // This is a significant discrepancy, safer to fail the operation.
          throw new ApiException(
            HttpStatus.BAD_REQUEST, // Or potentially HttpStatus.CONFLICT or HttpStatus.PRECONDITION_FAILED
            'DeviceContextMismatch',
            'Error.Auth.Device.Mismatch', // Consider a more specific error key if needed
            [{ code: 'Error.Auth.Device.SltContextMismatch', path: 'slt_token' }]
          )
        }
        const device = deviceFromFindOrCreate

        let shouldRememberDevice = body.rememberMe // Ưu tiên giá trị từ body nếu có
        if (shouldRememberDevice === undefined && sltContext?.metadata) {
          // Nếu body không cung cấp, kiểm tra metadata của SLT
          shouldRememberDevice = sltContext.metadata.rememberMe === true
        }
        shouldRememberDevice = shouldRememberDevice ?? false // Mặc định là false nếu không có thông tin nào

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

        // Quan trọng: Finalize SLT sau khi đã sử dụng thành công
        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) {
          this.tokenService.setTokenCookies(res, accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie)
          this.tokenService.clearSltCookie(res)
        }

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action =
          sltPurpose === TypeOfVerificationCode.LOGIN_2FA ? '2FA_VERIFY_SUCCESS' : 'UNTRUSTED_DEVICE_OTP_VERIFY_SUCCESS'
        auditLogEntry.details.finalizedSltJti = sltContext.sltJti

        return {
          userId: user.id,
          email: user.email,
          name: user.name,
          role: user.role.name,
          isDeviceTrustedInSession: accessTokenPayload.isDeviceTrustedInSession,
          currentDeviceId: device.id
        }
      }) // Kết thúc $transaction

      await this.auditLogService.recordAsync(auditLogEntry as AuditLogData)
      return resultFromTransaction
    } catch (error) {
      this.logger.error(`2FA/OTP verification failed: ${error.message}`, error.stack)
      auditLogEntry.errorMessage = error.message
      if (error instanceof ApiException) {
        auditLogEntry.details.apiErrorCode = error.errorCode
        auditLogEntry.details.apiHttpStatus = error.getStatus()
      } else {
        auditLogEntry.details.errorType = error.constructor.name
      }
      // Đảm bảo SLT được finalize và cookie SLT được xóa nếu có lỗi SAU KHI sltContext được lấy
      if (sltContext && sltContext.sltJti) {
        try {
          this.logger.warn(`Finalizing SLT JTI ${sltContext.sltJti} due to error in 2FA/OTP verification flow.`)
          await this.otpService.finalizeSlt(sltContext.sltJti)
        } catch (finalizeError) {
          this.logger.error(
            `Error finalizing SLT JTI ${sltContext.sltJti} during error handling: ${finalizeError.message}`
          )
        }
      }
      if (res && body.sltCookie) {
        // Chỉ xóa nếu sltCookie được cung cấp ban đầu
        this.logger.warn('Clearing SLT cookie due to error in 2FA/OTP verification flow.')
        this.tokenService.clearSltCookie(res)
      }

      await this.auditLogService.recordAsync(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
