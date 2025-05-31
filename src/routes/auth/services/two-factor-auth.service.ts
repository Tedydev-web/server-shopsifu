import { Injectable, HttpStatus, Logger } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { TwoFactorMethodType, TypeOfVerificationCode } from '../constants/auth.constants'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { DisableTwoFactorBodyType, TwoFactorVerifyBodyType } from 'src/routes/auth/auth.model'
import {
  InvalidTOTPException,
  TOTPAlreadyEnabledException,
  TOTPNotEnabledException,
  MaxVerificationAttemptsExceededException,
  EmailNotFoundException,
  InvalidPasswordException,
  DeviceSetupFailedException,
  SltCookieMissingException,
  SltContextInvalidPurposeException,
  InvalidRecoveryCodeException
} from 'src/routes/auth/auth.error'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { Response } from 'express'
import { Prisma } from '@prisma/client'
import { I18nContext, I18nService } from 'nestjs-i18n'
import envConfig from 'src/shared/config'
import { SessionManagementService } from './session-management.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { HashingService } from 'src/shared/services/hashing.service'
import { RolesService } from '../roles.service'
import { AuthRepository } from '../auth.repo'
import { EmailService } from '../providers/email.service'
import { TokenService } from '../providers/token.service'
import { TwoFactorService } from '../providers/2fa.service'
import { AuditLogService as AuditLogServiceType } from 'src/routes/audit-log/audit-log.service'
import { OtpService, SltContextData } from '../providers/otp.service'
import { DeviceService } from '../providers/device.service'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { JwtService } from '@nestjs/jwt'
import { HttpException } from '@nestjs/common'
import { SessionFinalizationService } from './session-finalization.service'
import { SltHelperService } from './slt-helper.service'
import { UserRepository } from '../repositories/shared-user.repo'

const MAX_2FA_VERIFY_ATTEMPTS = 5
const RECOVERY_CODES_COUNT = 8

@Injectable()
export class TwoFactorAuthService extends BaseAuthService {
  private readonly logger = new Logger(TwoFactorAuthService.name)

  constructor(
    prismaService: PrismaService,
    hashingService: HashingService,
    rolesService: RolesService,
    authRepository: AuthRepository,
    userRepository: UserRepository,
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
    private readonly sessionManagementService: SessionManagementService,
    private readonly sessionFinalizationService: SessionFinalizationService,
    private readonly sltHelperService: SltHelperService
  ) {
    super(
      prismaService,
      hashingService,
      rolesService,
      authRepository,
      userRepository,
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

  async setupTwoFactorAuth(userId: number, deviceId: number, ipAddress: string, userAgent: string) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: '2FA_SETUP_INITIATE_ATTEMPT',
      userId,
      ipAddress,
      userAgent,
      status: AuditLogStatus.FAILURE,
      details: {} as Prisma.JsonObject
    }

    try {
      const user = await this.userRepository.findUniqueWithDetails({ id: userId })
      if (!user) {
        auditLogEntry.errorMessage = 'User not found for 2FA setup.'
        auditLogEntry.details.reason = 'USER_NOT_FOUND_2FA_SETUP'
        throw new ApiException(HttpStatus.NOT_FOUND, 'UserNotFound', 'Error.Auth.UserNotFound')
      }
      auditLogEntry.userEmail = user.email

      if (user.twoFactorEnabled && user.twoFactorSecret) {
        auditLogEntry.errorMessage = '2FA is already enabled for this user.'
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        throw new TOTPAlreadyEnabledException()
      }

      const { secret, uri } = this.twoFactorService.generateTOTPSecret(user.email)

      const sltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: user.email,
        userId: userId,
        deviceId: deviceId,
        ipAddress: ipAddress,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.SETUP_2FA,
        metadata: { tempTwoFactorSecret: secret }
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'SETUP_2FA_INITIATED_WITH_SLT'
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        auditLogEntry.details.sltJti = sltJwt
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return {
        secret,
        uri,
        sltJwt
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
    sltCookieValue: string,
    totpCode: string,
    res: Response,
    requestIpAddress?: string,
    requestUserAgent?: string
  ) {
    const initialAuditDetails: Prisma.JsonObject = {
      userId,
      actionAttempted: 'CONFIRM_2FA_SETUP_WITH_SLT',
      sltCookieProvided: !!sltCookieValue,
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
      if (!sltCookieValue) {
        this.logger.error('[TwoFactorAuthService.confirmTwoFactorSetup] SLT cookie value is missing.')
        auditLogEntry.errorMessage = 'SLT cookie missing for 2FA setup confirmation'
        auditLogEntry.details.reason = 'SLT_COOKIE_MISSING_2FA_SETUP'
        throw new SltCookieMissingException()
      }

      if (!totpCode) {
        this.logger.warn('[TwoFactorAuthService.confirmTwoFactorSetup] TOTP code is missing.')
        auditLogEntry.errorMessage = 'TOTP code missing for 2FA setup confirmation'
        auditLogEntry.details.reason = 'TOTP_CODE_MISSING_2FA_SETUP'
        throw new ApiException(HttpStatus.BAD_REQUEST, 'TOTP_CODE_MISSING', 'Error.Auth.2FA.MissingTotpCode')
      }

      let sltContext: (SltContextData & { sltJti: string }) | null = null
      try {
        sltContext = await this.otpService.validateSltFromCookieAndGetContext(
          sltCookieValue,
          requestIpAddress || 'N/A',
          requestUserAgent || 'N/A',
          TypeOfVerificationCode.SETUP_2FA
        )

        if (sltContext) {
          auditLogEntry.details.sltPurpose = sltContext.purpose
          auditLogEntry.details.sltJti = sltContext.sltJti
          auditLogEntry.details.sltUserId = sltContext.userId
          auditLogEntry.details.sltDeviceId = sltContext.deviceId
        }
      } catch (error) {
        this.logger.error(
          `[TwoFactorAuthService.confirmTwoFactorSetup] SLT validation failed: ${error.message}`,
          error.stack
        )
        auditLogEntry.errorMessage = `SLT validation failed: ${error.message}`
        auditLogEntry.details.reason = 'SLT_VALIDATION_FAILED_2FA_SETUP'

        throw error
      }

      if (!sltContext) {
        this.logger.error('[TwoFactorAuthService.confirmTwoFactorSetup] SLT context is null after validation')
        auditLogEntry.errorMessage = 'SLT context is null after validation'
        auditLogEntry.details.reason = 'SLT_CONTEXT_NULL_AFTER_VALIDATION'
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'SltContextError', 'Error.Auth.Session.SltInvalid')
      }

      if (sltContext.purpose !== TypeOfVerificationCode.SETUP_2FA) {
        this.logger.error(
          `[TwoFactorAuthService.confirmTwoFactorSetup] Invalid SLT purpose: ${sltContext.purpose}. Expected: ${TypeOfVerificationCode.SETUP_2FA}`
        )
        auditLogEntry.errorMessage = `Invalid SLT purpose: ${sltContext.purpose}`
        auditLogEntry.details.reason = 'SLT_INVALID_PURPOSE_2FA_SETUP'

        throw new SltContextInvalidPurposeException()
      }

      if (sltContext.userId !== userId) {
        this.logger.error(
          `[TwoFactorAuthService.confirmTwoFactorSetup] User mismatch: SLT context user ${sltContext.userId}, request user ${userId}`
        )
        auditLogEntry.errorMessage = `User mismatch: SLT context user ${sltContext.userId}, request user ${userId}`
        auditLogEntry.details.reason = 'USER_MISMATCH_2FA_SETUP'

        throw new ApiException(HttpStatus.UNAUTHORIZED, 'Error.Auth.User.Mismatch', 'Error.Auth.Access.Unauthorized')
      }

      const resultFromTransaction = await this.prismaService.$transaction(async (tx) => {
        const user = await this.userRepository.findUniqueWithDetails({ id: userId }, tx)

        if (!user) {
          this.logger.error(
            `[TwoFactorAuthService.confirmTwoFactorSetup] User not found for ID: ${userId} during 2FA setup confirmation.`
          )
          auditLogEntry.errorMessage = `User not found for ID: ${userId}`
          auditLogEntry.details.reason = 'USER_NOT_FOUND_2FA_SETUP'
          throw new ApiException(HttpStatus.NOT_FOUND, 'USER_NOT_FOUND', 'Error.User.NotFound')
        }

        if (user.twoFactorEnabled) {
          this.logger.warn(
            `[TwoFactorAuthService.confirmTwoFactorSetup] 2FA is already enabled for user ${userId}. Method: ${user.twoFactorMethod}`
          )
          auditLogEntry.errorMessage = '2FA is already enabled for user'
          auditLogEntry.details.reason = 'TWO_FACTOR_ALREADY_ENABLED'
          auditLogEntry.details.existingTwoFactorMethod = user.twoFactorMethod
          throw new ApiException(HttpStatus.BAD_REQUEST, 'TWO_FACTOR_ALREADY_ENABLED', 'Error.Auth.2FA.AlreadyEnabled')
        }

        const twoFactorSecret = sltContext.metadata?.tempTwoFactorSecret as string
        if (!twoFactorSecret) {
          this.logger.error(
            `[TwoFactorAuthService.confirmTwoFactorSetup] No 2FA secret found in SLT metadata for user ${userId}`
          )
          auditLogEntry.errorMessage = 'No 2FA secret found in SLT metadata'
          auditLogEntry.details.reason = 'TWO_FACTOR_SECRET_MISSING'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'TWO_FACTOR_SECRET_MISSING', 'Error.Auth.2FA.SetupIncomplete')
        }

        const isValidTotp = this.twoFactorService.verifyTOTP({
          email: user.email,
          secret: twoFactorSecret,
          token: totpCode
        })
        this.logger.debug(`[TwoFactorService] Verifying TOTP for user: ${user.email}`)

        if (!isValidTotp) {
          this.logger.warn(`[TwoFactorAuthService.confirmTwoFactorSetup] Invalid TOTP code for user ${userId}`)
          auditLogEntry.errorMessage = 'Invalid TOTP code'
          auditLogEntry.details.reason = 'INVALID_TOTP_CODE'

          await this.sltHelperService.handleSltAttemptIncrementAndFinalization(
            sltContext.sltJti,
            MAX_2FA_VERIFY_ATTEMPTS,
            'confirmTwoFactorSetup-invalid-totp',
            auditLogEntry
          )

          throw new ApiException(HttpStatus.BAD_REQUEST, 'INVALID_TOTP_CODE', 'Error.Auth.2FA.InvalidCode')
        }

        this.logger.debug(`[TwoFactorService] Generating ${RECOVERY_CODES_COUNT} recovery codes`)
        const recoveryCodes = this.twoFactorService.generateRecoveryCodes(RECOVERY_CODES_COUNT)

        this.logger.debug(`[TwoFactorService] Saving ${recoveryCodes.length} recovery codes for user ${user.id}`)
        await this.twoFactorService.saveRecoveryCodes(user.id, recoveryCodes, tx)

        await tx.user.update({
          where: { id: user.id },
          data: {
            twoFactorEnabled: true,
            twoFactorMethod: TwoFactorMethodType.TOTP,
            twoFactorSecret: twoFactorSecret,
            passwordChangedAt: new Date()
          }
        })

        const device = await this.deviceService.findOrCreateDevice(
          {
            userId: user.id,
            userAgent: requestUserAgent || sltContext.userAgent || 'N/A',
            ip: requestIpAddress || sltContext.ipAddress || 'N/A'
          },
          tx
        )
        auditLogEntry.details.finalDeviceId = device.id

        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        auditLogEntry.details.sltFinalizedOnSuccess = sltContext.sltJti

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = '2FA_CONFIRM_SETUP_SUCCESS'
        if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
          auditLogEntry.details.userId = userId
        }

        return {
          recoveryCodes,
          message: await this.i18nService.translate('Auth.2FA.SetupSuccess', {
            lang: I18nContext.current()?.lang
          })
        }
      })

      await this.auditLogService.recordAsync(auditLogEntry as AuditLogData)
      return resultFromTransaction
    } catch (error) {
      this.logger.error(
        `[TwoFactorAuthService confirmTwoFactorSetup] Failed for user ${auditLogEntry.userEmail || userId || 'unknown'}: ${error.message}`,
        error.stack,
        auditLogEntry.details
      )
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage =
          error instanceof Error ? error.message : 'Unknown error during 2FA setup confirmation'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      auditLogEntry.status = AuditLogStatus.FAILURE
      await this.auditLogService.recordAsync(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async disableTwoFactorAuth(
    data: DisableTwoFactorBodyType & { userId: number; userAgent?: string; ip?: string; sltCookieValue?: string }
  ) {
    let sltContextToFinalize: (SltContextData & { sltJti: string }) | null = null
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'DISABLE_2FA_ATTEMPT',
      userId: data.userId,
      ipAddress: data.ip,
      userAgent: data.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        methodUsed: data.password ? 'password' : data.code ? 'totp' : data.recoveryCode ? 'recovery' : 'unknown',
        sltCookieProvided: !!data.sltCookieValue,
        codeProvided: !!data.code,
        recoveryCodeProvided: !!data.recoveryCode,
        passwordProvided: !!data.password
      }
    }

    try {
      const user = await this.userRepository.findUniqueWithDetails({ id: data.userId })
      if (!user) {
        auditLogEntry.errorMessage = 'User not found for disabling 2FA.'
        auditLogEntry.details.reason = 'USER_NOT_FOUND_DISABLE_2FA'
        throw EmailNotFoundException
      }
      auditLogEntry.userEmail = user.email

      if (!user.twoFactorEnabled || !user.twoFactorSecret) {
        auditLogEntry.errorMessage = '2FA is not enabled for this user.'
        auditLogEntry.details.reason = '2FA_NOT_ENABLED_DISABLE_ATTEMPT'
        throw TOTPNotEnabledException
      }

      let verificationSuccessful = false

      if (data.password) {
        const isPasswordValid = await this.hashingService.compare(data.password, user.password)
        if (!isPasswordValid) {
          auditLogEntry.errorMessage = 'Invalid password provided for disabling 2FA.'
          auditLogEntry.details.reason = 'INVALID_PASSWORD_DISABLE_2FA'
          throw InvalidPasswordException
        }
        verificationSuccessful = true
        auditLogEntry.details.passwordVerificationSuccess = true
      } else if (data.code || data.recoveryCode) {
        if (data.sltCookieValue) {
          try {
            sltContextToFinalize = await this.otpService.validateSltFromCookieAndGetContext(
              data.sltCookieValue,
              data.ip || 'N/A',
              data.userAgent || 'N/A',
              TypeOfVerificationCode.DISABLE_2FA
            )
            auditLogEntry.details.sltJti = sltContextToFinalize.sltJti
            auditLogEntry.details.sltPurpose = sltContextToFinalize.purpose
            auditLogEntry.details.sltUserId = sltContextToFinalize.userId

            if (sltContextToFinalize.userId !== user.id) {
              auditLogEntry.errorMessage = 'User ID mismatch between SLT context and current user for disabling 2FA.'
              auditLogEntry.details.reason = 'USER_ID_MISMATCH_SLT_DISABLE_2FA'
              throw new ApiException(HttpStatus.FORBIDDEN, 'AccessDenied', 'Error.Auth.AccessDenied')
            }
          } catch (sltError) {
            this.logger.warn(`Error validating SLT for 2FA disable (continuing): ${sltError.message}`)
            auditLogEntry.details.sltValidationError = sltError.message
          }
        }

        if (data.code) {
          const isValidTOTP = this.twoFactorService.verifyTOTP({
            email: user.email,
            secret: user.twoFactorSecret,
            token: data.code
          })
          if (!isValidTOTP) {
            auditLogEntry.errorMessage = 'Invalid TOTP code for disabling 2FA.'
            auditLogEntry.details.reason = 'INVALID_TOTP_DISABLE_2FA'

            if (sltContextToFinalize) {
              const newAttempts = await this.otpService.incrementSltAttempts(sltContextToFinalize.sltJti)
              auditLogEntry.details.sltAttempts = newAttempts
              if (newAttempts >= MAX_2FA_VERIFY_ATTEMPTS) {
                auditLogEntry.details.sltFinalizedMaxAttempts = true
                throw new MaxVerificationAttemptsExceededException()
              }
            }
            throw InvalidTOTPException
          }
          verificationSuccessful = true
          auditLogEntry.details.totpVerificationSuccess = true
        } else if (data.recoveryCode) {
          await this.twoFactorService.verifyRecoveryCode(user.id, data.recoveryCode, this.prismaService)
          verificationSuccessful = true
          auditLogEntry.details.recoveryCodeVerificationSuccess = true
        }
      } else {
        auditLogEntry.errorMessage =
          'No valid verification method (password, code, or recoveryCode) was provided in the request body structure, or schema validation failed.'
        auditLogEntry.details.reason = 'INVALID_REQUEST_STRUCTURE_DISABLE_2FA'
        throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.2FA.InvalidRequestStructure')
      }

      if (verificationSuccessful) {
        await this.prismaService.$transaction(async (tx) => {
          await this.userRepository.updateUser(
            { id: user.id },
            {
              twoFactorEnabled: false,
              twoFactorSecret: null,
              twoFactorMethod: null,
              twoFactorVerifiedAt: null
            },
            tx
          )
          await this.authRepository.deleteRecoveryCodesByUserId(user.id, tx)
          auditLogEntry.details.recoveryCodesDeleted = true

          if (sltContextToFinalize) {
            await this.otpService.finalizeSlt(sltContextToFinalize.sltJti)
            auditLogEntry.details.sltFinalizedOnSuccess = sltContextToFinalize.sltJti
          }
        })

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'DISABLE_2FA_SUCCESS'
        await this.auditLogService.record(auditLogEntry as AuditLogData)

        const message = await this.i18nService.translate('Auth.2FA.DisabledSuccessfully', {
          lang: I18nContext.current()?.lang
        })

        const lang = I18nContext.current()?.lang || 'en'
        const displayName = user.userProfile?.firstName || user.userProfile?.lastName || user.email
        this.emailService
          .sendSecurityAlertEmail({
            to: user.email,
            userName: displayName,
            alertSubject: await this.i18nService.translate('email.Email.SecurityAlert.Subject.2FADisabled', { lang }),
            alertTitle: await this.i18nService.translate('email.Email.SecurityAlert.Title.2FADisabled', { lang }),
            mainMessage: await this.i18nService.translate('email.Email.SecurityAlert.MainMessage.2FADisabled', {
              lang,
              args: { userName: displayName }
            }),
            actionDetails: [
              { label: 'Time', value: new Date().toLocaleString(lang) },
              { label: 'IP Address', value: data.ip || 'N/A' },
              { label: 'Device', value: data.userAgent || 'N/A' }
            ],
            secondaryMessage: await this.i18nService.translate(
              'email.Email.SecurityAlert.SecondaryMessage.NotYouEnable2FA',
              { lang }
            ),
            actionButtonText: await this.i18nService.translate('email.Email.SecurityAlert.Button.Enable2FA', { lang }),
            actionButtonUrl: `${envConfig.FRONTEND_URL}/account/security`
          })
          .catch((err) => {
            this.logger.error(`Failed to send 2FA disabled notification to ${user.email}: ${err.message}`, err.stack)
          })

        return { message }
      }
    } catch (error) {
      if (
        sltContextToFinalize &&
        !(auditLogEntry.details as any)?.sltFinalizedOnError &&
        !(auditLogEntry.details as any)?.sltFinalizedOnSuccess &&
        !(auditLogEntry.details as any)?.sltFinalizedUnexpectedFailure
      ) {
        this.logger.warn(
          `Attempting to finalize SLT ${sltContextToFinalize.sltJti} in outer catch block for disable2FA (verification not successful or other error)`
        )
        await this.otpService
          .finalizeSlt(sltContextToFinalize.sltJti)
          .catch((ef) =>
            this.logger.error(
              `Error finalizing SLT ${sltContextToFinalize?.sltJti} in outer catch (disable 2FA): ${ef.message}`
            )
          )
        ;(auditLogEntry.details as Prisma.JsonObject).sltFinalizedOuterCatch = sltContextToFinalize.sltJti
      }

      if (!(error instanceof ApiException) && !(error instanceof HttpException)) {
        this.logger.error(`Unexpected error during disable 2FA: ${error.message}`, error.stack)
      }

      if (!auditLogEntry.errorMessage && error instanceof Error) {
        auditLogEntry.errorMessage = error.message
      }
      if (!auditLogEntry.details.reason && error instanceof ApiException) {
        auditLogEntry.details.reason = error.errorCode
      } else if (!auditLogEntry.details.reason) {
        auditLogEntry.details.reason = 'UNHANDLED_EXCEPTION_DISABLE_2FA'
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async verifyTwoFactor(
    body: TwoFactorVerifyBodyType & { userAgent: string; ip: string },
    sltContext: SltContextData & { sltJti: string },
    res?: Response
  ) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: '2FA_VERIFY_ATTEMPT',
      userId: sltContext.userId,
      userEmail: sltContext.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        sltJti: sltContext.sltJti,
        sltPurpose: sltContext.purpose,
        sltDeviceId: sltContext.deviceId,
        codeProvided: !!body.code,
        recoveryCodeProvided: !!body.recoveryCode
      }
    }

    try {
      if (!res) {
        this.logger.error(
          '[verifyTwoFactor] Response object (res) is required but was not provided. Cannot finalize session.'
        )
        auditLogEntry.errorMessage = 'Response object missing, cannot finalize session.'
        auditLogEntry.details.reason = 'MISSING_RESPONSE_OBJECT_2FA_VERIFY'

        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }

      const user = await this.userRepository.findUniqueWithDetails({ id: sltContext.userId })
      if (!user || !user.role) {
        auditLogEntry.errorMessage = 'User not found from SLT context for 2FA verification.'
        auditLogEntry.details.reason = 'USER_NOT_FOUND_2FA_VERIFY_SLT'
        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        throw new EmailNotFoundException()
      }
      auditLogEntry.userEmail = user.email

      if (!user.twoFactorEnabled || !user.twoFactorSecret || !user.twoFactorMethod) {
        auditLogEntry.errorMessage = '2FA is not enabled for user attempting 2FA verification.'
        auditLogEntry.details.reason = 'TWO_FACTOR_NOT_ENABLED'
        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        throw new TOTPNotEnabledException()
      }

      // Kiểm tra xem người dùng đã cung cấp mã TOTP hay recovery code
      if (!body.code && !body.recoveryCode) {
        auditLogEntry.errorMessage = 'Neither TOTP code nor recovery code provided for 2FA verification.'
        auditLogEntry.details.reason = 'NO_VERIFICATION_CODE_PROVIDED'
        const newAttempts = await this.otpService.incrementSltAttempts(sltContext.sltJti)
        auditLogEntry.details.sltAttempts = newAttempts
        if (newAttempts >= MAX_2FA_VERIFY_ATTEMPTS) {
          await this.otpService.finalizeSlt(sltContext.sltJti)
          if (res) this.tokenService.clearSltCookie(res)
          throw new MaxVerificationAttemptsExceededException()
        }
        throw new ApiException(HttpStatus.BAD_REQUEST, 'NO_VERIFICATION_CODE', 'Error.Auth.2FA.NoVerificationCode')
      }

      // Xác thực mã TOTP hoặc recovery code
      let verificationMethod = ''
      if (body.code) {
        // Xác thực TOTP
        const isValid = this.twoFactorService.verifyTOTP({
          email: user.email,
          secret: user.twoFactorSecret,
          token: body.code
        })

        if (!isValid) {
          auditLogEntry.errorMessage = 'Invalid TOTP code provided for 2FA verification.'
          auditLogEntry.details.reason = 'INVALID_TOTP_CODE'
          const newAttempts = await this.otpService.incrementSltAttempts(sltContext.sltJti)
          auditLogEntry.details.sltAttempts = newAttempts
          if (newAttempts >= MAX_2FA_VERIFY_ATTEMPTS) {
            await this.otpService.finalizeSlt(sltContext.sltJti)
            if (res) this.tokenService.clearSltCookie(res)
            throw new MaxVerificationAttemptsExceededException()
          }
          throw new InvalidTOTPException()
        }
        verificationMethod = 'TOTP'
      } else if (body.recoveryCode) {
        // Xác thực recovery code
        try {
          await this.twoFactorService.verifyRecoveryCode(user.id, body.recoveryCode, this.prismaService)
          verificationMethod = 'RECOVERY'
        } catch (error) {
          auditLogEntry.errorMessage = 'Invalid recovery code provided for 2FA verification.'
          auditLogEntry.details.reason = 'INVALID_RECOVERY_CODE'
          const newAttempts = await this.otpService.incrementSltAttempts(sltContext.sltJti)
          auditLogEntry.details.sltAttempts = newAttempts
          if (newAttempts >= MAX_2FA_VERIFY_ATTEMPTS) {
            await this.otpService.finalizeSlt(sltContext.sltJti)
            if (res) this.tokenService.clearSltCookie(res)
            throw new MaxVerificationAttemptsExceededException()
          }
          throw new InvalidRecoveryCodeException()
        }
      }

      let deviceToUse = await this.deviceService.findDeviceById(sltContext.deviceId)
      if (!deviceToUse) {
        this.logger.warn(
          `Device ID ${sltContext.deviceId} from SLT context not found. Attempting to create or find matching device for user ${user.id}`
        )
        deviceToUse = await this.deviceService.findOrCreateDevice({
          userId: user.id,
          userAgent: body.userAgent,
          ip: body.ip
        })
        auditLogEntry.details.deviceRecreatedOrFound = deviceToUse.id
      } else if (deviceToUse.userId !== user.id) {
        this.logger.error(
          `Device ID ${sltContext.deviceId} from SLT context belongs to user ${deviceToUse.userId}, but SLT context is for user ${user.id}. Critical mismatch.`
        )
        auditLogEntry.errorMessage = 'Device in SLT context does not belong to the authenticated user.'
        auditLogEntry.details.reason = 'DEVICE_USER_MISMATCH_SLT_2FA'
        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        throw new DeviceSetupFailedException()
      }

      const userForFinalization = {
        ...user,
        userProfile: user.userProfile,
        role: {
          id: user.role.id,
          name: user.role.name
        }
      }

      const finalizationResult = await this.sessionFinalizationService.finalizeSuccessfulAuthentication({
        user: userForFinalization,
        device: deviceToUse,
        rememberMe: body.rememberMe === undefined ? true : body.rememberMe,
        ipAddress: body.ip,
        userAgent: body.userAgent,
        source: '2fa-verification',
        res,
        sltToFinalize: { jti: sltContext.sltJti, purpose: sltContext.purpose as TypeOfVerificationCode }
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = '2FA_VERIFY_SUCCESS'
      auditLogEntry.details.finalDeviceId = deviceToUse.id
      auditLogEntry.details.finalSessionId = finalizationResult.sessionId
      auditLogEntry.details.finalAccessTokenJti = finalizationResult.accessTokenJti
      auditLogEntry.details.isTwoFactorAuthenticated = true
      auditLogEntry.details.verificationMethodUsed = verificationMethod
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return {
        ...finalizationResult
      }
    } catch (error) {
      if (!auditLogEntry.errorMessage && error instanceof Error) {
        auditLogEntry.errorMessage = error.message
      }
      if (!auditLogEntry.details.reason && error instanceof ApiException) {
        auditLogEntry.details.reason = error.errorCode
      } else if (!auditLogEntry.details.reason) {
        auditLogEntry.details.reason = 'UNHANDLED_EXCEPTION_IN_2FA_VERIFY'
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async regenerateRecoveryCodes(userId: number, ip?: string, userAgent?: string): Promise<{ recoveryCodes: string[] }> {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: '2FA_REGENERATE_RECOVERY_CODES_ATTEMPT',
      userId,
      ipAddress: ip,
      userAgent,
      status: AuditLogStatus.FAILURE,
      details: { userId } as Prisma.JsonObject
    }

    try {
      const user = await this.userRepository.findUniqueWithDetails({ id: userId })
      if (!user || !user.role) {
        auditLogEntry.errorMessage = 'User not found.'
        throw EmailNotFoundException
      }
      auditLogEntry.userEmail = user.email

      if (!user.twoFactorEnabled || user.twoFactorMethod !== TwoFactorMethodType.TOTP) {
        auditLogEntry.errorMessage = '2FA (TOTP) is not enabled for this user.'
        throw TOTPNotEnabledException
      }

      const newRecoveryCodes = this.twoFactorService.generateRecoveryCodes()
      await this.twoFactorService.saveRecoveryCodes(userId, newRecoveryCodes, this.prismaService)

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = '2FA_REGENERATE_RECOVERY_CODES_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      const lang = I18nContext.current()?.lang || 'en'
      const displayName = user.userProfile?.firstName || user.userProfile?.lastName || user.email
      try {
        await this.emailService.sendSecurityAlertEmail({
          to: user.email,
          userName: displayName,
          alertSubject: await this.i18nService.translate(
            'email.Email.SecurityAlert.Subject.2FARecoveryCodesRegenerated',
            { lang }
          ),
          alertTitle: await this.i18nService.translate('email.Email.SecurityAlert.Title.2FARecoveryCodesRegenerated', {
            lang
          }),
          mainMessage: await this.i18nService.translate(
            'email.Email.SecurityAlert.MainMessage.2FARecoveryCodesRegenerated',
            {
              lang,
              args: { userName: displayName }
            }
          ),
          actionDetails: [
            { label: 'Time', value: new Date().toLocaleString(lang) },
            { label: 'IP Address', value: ip || 'N/A' },
            { label: 'Device', value: userAgent || 'N/A' }
          ],
          secondaryMessage: await this.i18nService.translate(
            'email.Email.SecurityAlert.SecondaryMessage.NotYouKeepSafe',
            { lang }
          ),
          actionButtonText: await this.i18nService.translate('email.Email.SecurityAlert.Button.SecureAccount', {
            lang
          }),
          actionButtonUrl: `${envConfig.FRONTEND_URL}/account/security`
        })
      } catch (emailError) {
        this.logger.error(
          `Failed to send 2FA recovery codes regenerated notification to ${user.email}: ${emailError.message}`
        )
      }

      return { recoveryCodes: newRecoveryCodes }
    } catch (error) {
      auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
