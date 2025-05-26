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
            actionButtonUrl: `${envConfig.FRONTEND_HOST_URL}/account/sessions`
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
            actionButtonUrl: `${envConfig.FRONTEND_HOST_URL}/account/security`
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
      userEmail: body.email, // Initial, will be updated if SLT context is valid
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        emailProvidedInBody: body.email,
        rememberMe: body.rememberMe,
        sltCookieProvided: !!body.sltCookie,
        bodyHasEmail: !!body.email // Log if email was in body
      } as Prisma.JsonObject
    }

    let sltContext: Awaited<ReturnType<typeof this.otpService.validateSltFromCookieAndGetContext>> | null = null
    let effectiveEmail: string | undefined = body.email // Initialize with body email
    let effectiveUserId: number | undefined = undefined

    try {
      if (body.sltCookie) {
        sltContext = await this.otpService.validateSltFromCookieAndGetContext(
          body.sltCookie,
          body.ip,
          body.userAgent,
          TypeOfVerificationCode.LOGIN_2FA
        )

        if (sltContext && sltContext.userId) {
          effectiveUserId = sltContext.userId
          auditLogEntry.userId = effectiveUserId // Update audit log with user ID from SLT context
          auditLogEntry.details.sltJti = sltContext.sltJti
          auditLogEntry.details.sltPurpose = sltContext.purpose
          auditLogEntry.details.sltDeviceId = sltContext.deviceId
          auditLogEntry.details.userIdFromSlt = effectiveUserId

          // If SLT context has an email, it should be the source of truth
          if (sltContext.email) {
            effectiveEmail = sltContext.email
            auditLogEntry.userEmail = effectiveEmail // Update audit log
            auditLogEntry.details.emailFromSlt = effectiveEmail
            if (body.email && body.email !== sltContext.email) {
              this.logger.warn(
                `Email mismatch: SLT context email ('${sltContext.email}') differs from body email ('${body.email}') for SLT JTI ${sltContext.sltJti}. Prioritizing SLT email.`
              )
              auditLogEntry.details.emailMismatchWarning = `SLT: ${sltContext.email}, Body: ${body.email}`
            }
          } else {
            // This case should ideally not happen if SLT is created correctly with email.
            // If SLT is valid but doesn't have email, and body doesn't have email, it's an issue.
            this.logger.warn(
              `SLT context for JTI ${sltContext.sltJti} is missing email. Falling back to body email if present.`
            )
            if (!body.email) {
              auditLogEntry.errorMessage = 'Email is required for 2FA verification (missing in SLT context and body).'
              auditLogEntry.details.reason = 'MISSING_EMAIL_SLT_AND_BODY'
              throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Email.NotFound', [
                { code: 'validation.email.required', path: 'email' }
              ])
            }
            // effectiveEmail is already body.email, so no change needed here.
          }
        } else {
          // SLT cookie provided, but context was invalid or didn't yield a userId
          auditLogEntry.errorMessage = 'Invalid or expired SLT context from cookie for 2FA verification.'
          auditLogEntry.details.reason = 'INVALID_SLT_CONTEXT_FROM_COOKIE'
          // If SLT was mandatory and failed, we should throw.
          // For now, if body.email exists, we might proceed, but this path implies a misconfiguration or error.
          // Let's assume if sltCookie is present, it MUST be valid.
          throw MismatchedSessionTokenException // Or a more specific SLT error
        }
      } else {
        // No SLT cookie provided
        auditLogEntry.details.sltCookieMissing = true
        if (!body.email) {
          auditLogEntry.errorMessage = 'Email is required for 2FA verification (SLT cookie not provided).'
          auditLogEntry.details.reason = 'MISSING_EMAIL_NO_SLT'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Email.NotFound', [
            { code: 'validation.email.required', path: 'email' }
          ])
        }
        // effectiveEmail is already body.email. Need to find userId based on this email.
        // This branch means we are falling back to a non-SLT flow or a flow where SLT was not initiated.
        this.logger.warn('No SLT cookie provided for 2FA. Proceeding with email from body if available.')
      }

      // At this point, effectiveEmail should be set if we are to proceed.
      if (!effectiveEmail) {
        // This is a safeguard, should have been caught by earlier checks.
        auditLogEntry.errorMessage = 'Effective email could not be determined for 2FA verification.'
        auditLogEntry.details.reason = 'EFFECTIVE_EMAIL_UNDETERMINED'
        throw EmailNotFoundException // Or a generic bad request
      }

      // If userId is not yet determined (e.g., no valid SLT context), fetch user by effectiveEmail.
      // If userId was determined from SLT, this step is mainly to fetch the full user object.
      const userLookupCriteria = effectiveUserId ? { id: effectiveUserId } : { email: effectiveEmail! }

      const resultFromTransaction = await this.prismaService.$transaction(async (tx) => {
        const user = await this.sharedUserRepository.findUniqueWithRole(userLookupCriteria, tx)

        if (!user || !user.role) {
          auditLogEntry.errorMessage = 'User or user role not found.'
          auditLogEntry.details.reason = 'USER_OR_ROLE_NOT_FOUND'
          auditLogEntry.userEmail = effectiveEmail // Log the email used for lookup
          throw EmailNotFoundException
        }

        // Update effectiveUserId if it wasn't set from SLT (i.e., looked up by email)
        if (!effectiveUserId) {
          effectiveUserId = user.id
        }
        auditLogEntry.userId = effectiveUserId // Ensure audit log has the final userId
        auditLogEntry.userEmail = user.email // Ensure audit log has the final email

        if (!user.twoFactorEnabled || !user.twoFactorSecret || !user.twoFactorMethod) {
          auditLogEntry.errorMessage = 'User 2FA not configured or secret/method missing.'
          auditLogEntry.details.reason = 'USER_2FA_NOT_CONFIGURED'
          throw TOTPNotEnabledException
        }

        let isValidCode = false
        let recoveryCodeUsed = false

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

        if (sltPurpose === TypeOfVerificationCode.LOGIN_2FA) {
          if (body.recoveryCode) {
            if (
              user.twoFactorMethod !== TwoFactorMethodType.RECOVERY &&
              user.twoFactorMethod !== TwoFactorMethodType.TOTP // TOTP method also has recovery codes
            ) {
              auditLogEntry.errorMessage = 'Recovery code used with incompatible 2FA method for LOGIN_2FA purpose.'
              auditLogEntry.details.reason = 'RECOVERY_CODE_INVALID_METHOD_FOR_2FA'
              throw InvalidRecoveryCodeException
            }
            const recoveryCodeResult = await this.twoFactorService.verifyRecoveryCode(user.id, body.recoveryCode, tx)
            isValidCode = !!recoveryCodeResult
            if (isValidCode) {
              auditLogEntry.details.twoFactorMethodUsed = TwoFactorMethodType.RECOVERY
              recoveryCodeUsed = true
            } else {
              auditLogEntry.errorMessage = 'Invalid recovery code for LOGIN_2FA.'
              auditLogEntry.details.reason = 'INVALID_RECOVERY_CODE_FOR_2FA'
            }
          } else if (body.code) {
            if (user.twoFactorMethod !== TwoFactorMethodType.TOTP) {
              auditLogEntry.errorMessage =
                'TOTP code (from body.code) used with non-TOTP 2FA method for LOGIN_2FA purpose.'
              auditLogEntry.details.reason = 'TOTP_CODE_INVALID_METHOD_FOR_2FA'
              throw InvalidTOTPException
            }
            isValidCode = this.twoFactorService.verifyTOTP({
              email: user.email,
              secret: user.twoFactorSecret!,
              token: body.code
            })
            if (isValidCode) {
              auditLogEntry.details.twoFactorMethodUsed = TwoFactorMethodType.TOTP
            } else {
              auditLogEntry.errorMessage = 'Invalid TOTP code (from body.code) for LOGIN_2FA.'
              auditLogEntry.details.reason = 'INVALID_TOTP_CODE_FOR_2FA'
            }
          } else {
            auditLogEntry.errorMessage = 'Neither code nor recovery code was provided for LOGIN_2FA purpose.'
            auditLogEntry.details.reason = 'NO_2FA_CODE_PROVIDED_FOR_2FA'
            throw InvalidCodeFormatException
          }
        } else if (sltPurpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP) {
          if (body.code) {
            // For untrusted device OTP, we use verifyOtpOnly
            // Ensure effectiveEmail is available and correct from SLT context or body
            const emailForOtpVerification = sltContext.email || effectiveEmail
            if (!emailForOtpVerification) {
              auditLogEntry.errorMessage = 'Email not found in SLT context or body for OTP verification.'
              auditLogEntry.details.reason = 'EMAIL_MISSING_FOR_UNTRUSTED_OTP'
              throw EmailNotFoundException
            }
            isValidCode = await this.otpService.verifyOtpOnly(
              emailForOtpVerification,
              body.code,
              TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
              user.id, // For audit logging
              body.ip,
              body.userAgent
            )
            if (isValidCode) {
              auditLogEntry.details.verificationMethod = 'OTP_UNTRUSTED_DEVICE'
            } else {
              auditLogEntry.errorMessage = 'Invalid OTP (from body.code) for LOGIN_UNTRUSTED_DEVICE_OTP.'
              auditLogEntry.details.reason = 'INVALID_OTP_FOR_UNTRUSTED_DEVICE'
            }
          } else {
            auditLogEntry.errorMessage = 'Code was not provided for LOGIN_UNTRUSTED_DEVICE_OTP purpose.'
            auditLogEntry.details.reason = 'NO_CODE_PROVIDED_FOR_UNTRUSTED_OTP'
            throw InvalidCodeFormatException
          }
        } else {
          // Should not happen if SLT purpose validation is correct earlier
          auditLogEntry.errorMessage = `Unsupported SLT purpose for 2FA/OTP verification: ${sltPurpose}`
          auditLogEntry.details.reason = 'UNSUPPORTED_SLT_PURPOSE_FOR_VERIFICATION'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Session.InvalidLogin')
        }

        if (!isValidCode) {
          // Error message and reason should have been set in the blocks above
          if (sltPurpose === TypeOfVerificationCode.LOGIN_2FA) {
            throw body.recoveryCode ? InvalidRecoveryCodeException : InvalidTOTPException
          } else if (sltPurpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP) {
            throw InvalidCodeFormatException
          }
          // Fallback, though specific exceptions should be thrown above
          throw InvalidCodeFormatException
        }

        // Device handling:
        if (sltContext) {
          // SLT flow was initiated and context is valid
          if (!sltContext.deviceId) {
            auditLogEntry.errorMessage = `SLT context (JTI: ${sltContext.sltJti}) is missing deviceId, which is required for 2FA verification.`
            auditLogEntry.details.reason = 'SLT_CONTEXT_MISSING_DEVICEID'
            this.logger.error(auditLogEntry.errorMessage)
          throw new ApiException(
              HttpStatus.INTERNAL_SERVER_ERROR,
              'SltProcessingError',
              'Error.Auth.Session.InvalidLogin'
            )
          }

          const deviceIdFromSlt = sltContext.deviceId
          const device = await this.deviceService.findDeviceById(deviceIdFromSlt, tx)

          if (!device) {
            auditLogEntry.errorMessage = `Device with ID ${deviceIdFromSlt} from SLT context not found.`
            auditLogEntry.details.reason = 'DEVICE_NOT_FOUND_FROM_SLT'
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'DeviceNotFound', 'Error.Auth.Device.Invalid')
          }
          // Potentially update IP and lastActive on the device from SLT context
          await this.deviceService.updateDevice(device.id, { ip: body.ip, lastActive: new Date() }, tx)

          auditLogEntry.details.finalDeviceId = device.id

          const rememberMe = body.rememberMe || false
          let finalDeviceIsTrusted = device.isTrusted

          if (rememberMe && !device.isTrusted) {
            await this.deviceService.trustDevice(device.id, user.id, tx)
            finalDeviceIsTrusted = true
            auditLogEntry.details.deviceTrustedDueToRememberMe = true
          }
          auditLogEntry.details.rememberMeEnabled = rememberMe
          auditLogEntry.details.finalDeviceTrustedStatus = finalDeviceIsTrusted

          const newSessionIdGenerated = uuidv4() // Renamed to avoid conflict
          await this.sessionManagementService.enforceSessionAndDeviceLimits(user.id, newSessionIdGenerated, device.id)

        const { accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie, accessTokenJti } =
          await this.tokenService.generateTokens(
            {
              userId: user.id,
              deviceId: device.id,
              roleId: user.roleId,
              roleName: user.role.name,
                sessionId: newSessionIdGenerated
            },
            tx,
            rememberMe
          )

        if (res) {
          this.tokenService.setTokenCookies(res, accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie)
            // SLT cookie will be cleared after transaction success
          }

          await this.authRepository.updateUser({ id: user.id }, { twoFactorVerifiedAt: new Date() }, tx)

          const sessionDetailsForRedis = {
            userId: user.id,
            deviceId: device.id,
            ipAddress: body.ip,
            userAgent: body.userAgent,
            createdAt: new Date().toISOString(),
            lastActiveAt: new Date().toISOString(),
            isTrusted: finalDeviceIsTrusted,
            rememberMe: rememberMe,
            roleId: user.roleId,
            roleName: user.role.name,
            currentAccessTokenJti: accessTokenJti,
            currentRefreshTokenJti: refreshTokenJti,
            sessionId: newSessionIdGenerated // Use the renamed variable
          }

          return {
            ...sessionDetailsForRedis,
            accessToken,
            refreshTokenJti,
            maxAgeForRefreshTokenCookie,
            user, // Return user object from transaction scope
            finalDeviceIsTrusted,
            newSessionId: newSessionIdGenerated, // Return the new session ID
            sltJtiToFinalize: sltContext!.sltJti // Pass JTI if SLT flow
          }
        } else {
          // This block implies no SLT cookie was provided.
          // For a 2FA verification step after login, an SLT should typically be involved.
          auditLogEntry.errorMessage =
            'A valid session link (SLT) is required for this 2FA verification step but was not found.'
          auditLogEntry.details.reason = 'MISSING_SLT_FOR_2FA_VERIFICATION'
          this.logger.error(
            `Critical error: Attempting 2FA verification without a valid SLT context. Effective UserID: ${effectiveUserId}, Effective Email: ${effectiveEmail}`
          )
          throw new ApiException(
            HttpStatus.BAD_REQUEST, // Or INTERNAL_SERVER_ERROR if this state is truly unexpected
            'SltMissingError',
            'Error.Auth.Session.InvalidLogin' // Re-evaluate error code/message
          )
        }
      }) // End of transaction

      // All subsequent logic depends on resultFromTransaction, so it must be inside the try block
      // and after the transaction has successfully completed.

      // Transaction successful
      if (resultFromTransaction.sltJtiToFinalize) {
        // Check the returned JTI
        await this.otpService.finalizeSlt(resultFromTransaction.sltJtiToFinalize) // Use it
        if (res) {
          const sltCookieConfig = envConfig.cookie.sltToken
          res.clearCookie(sltCookieConfig.name, { path: sltCookieConfig.path, domain: sltCookieConfig.domain })
          this.logger.debug(
            `[Verify2FA] SLT cookie (${sltCookieConfig.name}) cleared after successful 2FA verification.`
          )
        }
      }

      const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${resultFromTransaction.newSessionId}`
      const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${resultFromTransaction.user.id}` // Corrected: Use user.id from the user object in result
      const absoluteSessionLifetimeSeconds = Math.floor(envConfig.ABSOLUTE_SESSION_LIFETIME_MS / 1000)

      const redisSessionData: Record<string, string | number | boolean> = {
        userId: resultFromTransaction.user.id, // Corrected
        deviceId: resultFromTransaction.deviceId,
        ipAddress: resultFromTransaction.ipAddress,
        userAgent: resultFromTransaction.userAgent,
        createdAt: resultFromTransaction.createdAt,
        lastActiveAt: resultFromTransaction.lastActiveAt,
        isTrusted: resultFromTransaction.isTrusted,
        rememberMe: resultFromTransaction.rememberMe,
        roleId: resultFromTransaction.roleId,
        roleName: resultFromTransaction.roleName,
        currentAccessTokenJti: resultFromTransaction.currentAccessTokenJti,
        currentRefreshTokenJti: resultFromTransaction.currentRefreshTokenJti
      }

      await this.redisService.pipeline((pipeline) => {
        pipeline.hmset(sessionKey, redisSessionData)
        pipeline.expire(sessionKey, absoluteSessionLifetimeSeconds)
        pipeline.sadd(userSessionsKey, resultFromTransaction.newSessionId)
        return pipeline
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = '2FA_VERIFY_SUCCESS_LOGIN_COMPLETED'
      auditLogEntry.details.sessionId = resultFromTransaction.newSessionId
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      const i18nLang = I18nContext.current()?.lang
      let message = await this.i18nService.translate('Auth.2FA.Verify.Success', { lang: i18nLang })
      if (!resultFromTransaction.finalDeviceIsTrusted) {
        message = await this.i18nService.translate('Auth.2FA.Verify.AskToTrustDevice', { lang: i18nLang })
      }

      return {
        message,
        userId: resultFromTransaction.user.id, // Corrected
        email: resultFromTransaction.user.email, // Corrected
        name: resultFromTransaction.user.name, // Corrected
        role: resultFromTransaction.user.role, // Corrected
        isDeviceTrustedInSession: resultFromTransaction.finalDeviceIsTrusted,
        currentDeviceId: resultFromTransaction.deviceId
      }
    } catch (error) {
      auditLogEntry.errorMessage = error instanceof Error ? error.message : String(error)
      if (error instanceof ApiException && error.details) {
        auditLogEntry.details.originalError = error.details as unknown as Prisma.JsonObject[]
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      this.logger.error(
        `2FA verification failed for email ${effectiveEmail} (user ${effectiveUserId}): ${error.message}`,
        error.stack,
        `Details: ${JSON.stringify(auditLogEntry.details)}`
      )
      if (sltContext && sltContext.sltJti) {
        // Consider if SLT context should be finalized on failure in some cases,
        // e.g., if it's a one-time use regardless of success/failure of the 2FA code itself.
        // For now, it's only finalized on success.
      }
      if (res) {
        // Clear SLT cookie on error too, as it might be invalid or one-time
        const sltCookieConfig = envConfig.cookie.sltToken
        res.clearCookie(sltCookieConfig.name, { path: sltCookieConfig.path, domain: sltCookieConfig.domain })
        this.logger.debug(
          `[Verify2FA] SLT cookie (${sltCookieConfig.name}) cleared due to error during 2FA verification.`
        )
      }
      throw error
    }
  }
}
