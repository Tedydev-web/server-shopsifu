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
  DeviceSetupFailedException
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
import { OtpService } from '../providers/otp.service'
import { DeviceService } from '../providers/device.service'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { JwtService } from '@nestjs/jwt'
import { SltContextData } from '../providers/otp.service'
import { HttpException } from '@nestjs/common'
import { SessionFinalizationService } from './session-finalization.service'
import { SltHelperService } from './slt-helper.service'
import { UserRepository } from '../repositories/shared-user.repo'

const MAX_2FA_VERIFY_ATTEMPTS = 5

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
      const resultFromTransaction = await this.prismaService.$transaction(async (tx) => {
        const user = await this.userRepository.findUniqueWithDetails({ id: userId }, tx)
        if (!user || !user.role) {
          auditLogEntry.errorMessage = 'User not found during 2FA confirmation.'
          auditLogEntry.details.reason = 'USER_NOT_FOUND_2FA_CONFIRM'
          throw new EmailNotFoundException()
        }
        auditLogEntry.userEmail = user.email

        if (user.twoFactorEnabled && user.twoFactorMethod === TwoFactorMethodType.TOTP) {
          auditLogEntry.errorMessage = '2FA (TOTP) is already enabled for this user.'
          auditLogEntry.details.reason = '2FA_ALREADY_ENABLED_CONFIRM'
          throw new TOTPAlreadyEnabledException()
        }

        const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
          sltCookieValue,
          requestIpAddress || 'N/A',
          requestUserAgent || 'N/A',
          TypeOfVerificationCode.SETUP_2FA
        )
        auditLogEntry.details.sltJti = sltContext.sltJti
        auditLogEntry.details.sltContextUserId = sltContext.userId

        if (sltContext.userId !== userId) {
          auditLogEntry.errorMessage = 'User ID mismatch between SLT context and request.'
          auditLogEntry.details.reason = 'USER_ID_MISMATCH_SLT_CONFIRM'
          await this.otpService.finalizeSlt(sltContext.sltJti)
          if (res) this.tokenService.clearSltCookie(res)
          throw new ApiException(HttpStatus.FORBIDDEN, 'AccessDenied', 'Error.Auth.AccessDenied')
        }

        const tempTwoFactorSecret = sltContext.metadata?.tempTwoFactorSecret as string | undefined
        if (!tempTwoFactorSecret) {
          auditLogEntry.errorMessage = 'Temporary 2FA secret missing from SLT context.'
          auditLogEntry.details.reason = 'MISSING_TEMP_SECRET_IN_SLT'
          await this.otpService.finalizeSlt(sltContext.sltJti)
          if (res) this.tokenService.clearSltCookie(res)
          throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'SltProcessingError', 'Error.Auth.2FA.SetupFailed')
        }

        const isValidTOTP = this.twoFactorService.verifyTOTP({
          email: user.email,
          secret: tempTwoFactorSecret,
          token: totpCode
        })

        if (!isValidTOTP) {
          auditLogEntry.errorMessage = 'Invalid TOTP code provided during 2FA setup confirmation (SLT).'
          auditLogEntry.details.reason = 'INVALID_TOTP_CODE_SLT_CONFIRM'
          await this.sltHelperService.handleSltAttemptIncrementAndFinalization(
            sltContext.sltJti,
            MAX_2FA_VERIFY_ATTEMPTS,
            'confirmTwoFactorSetup',
            auditLogEntry,
            res
          )
          throw new InvalidTOTPException()
        }

        const recoveryCodes = this.twoFactorService.generateRecoveryCodes()
        await this.twoFactorService.saveRecoveryCodes(userId, recoveryCodes, tx)
        auditLogEntry.details.recoveryCodesGeneratedCount = recoveryCodes.length

        await this.userRepository.updateUser(
          { id: userId },
          {
            twoFactorEnabled: true,
            twoFactorSecret: tempTwoFactorSecret,
            twoFactorMethod: TwoFactorMethodType.TOTP,
            twoFactorVerifiedAt: new Date()
          },
          tx
        )
        auditLogEntry.details.twoFactorMethodSet = TwoFactorMethodType.TOTP

        const device = await this.deviceService.findOrCreateDevice(
          {
            userId: user.id,
            userAgent: requestUserAgent || sltContext.userAgent || 'N/A',
            ip: requestIpAddress || sltContext.ipAddress || 'N/A'
          },
          tx
        )
        auditLogEntry.details.finalDeviceId = device.id

        if (!device.isTrusted) {
          await this.deviceService.trustDevice(device.id, user.id, tx)
          auditLogEntry.details.deviceTrustedInThisFlow = true
        }

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
        if (!data.sltCookieValue) {
          auditLogEntry.errorMessage = 'SLT cookie is required when disabling 2FA with TOTP/Recovery code.'
          auditLogEntry.details.reason = 'MISSING_SLT_FOR_CODE_DISABLE_2FA'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'SltTokenMissing', 'Error.Auth.Session.InvalidLogin')
        }

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

          if (data.code) {
            const isValidTOTP = this.twoFactorService.verifyTOTP({
              email: user.email,
              secret: user.twoFactorSecret,
              token: data.code
            })
            if (!isValidTOTP) {
              auditLogEntry.errorMessage = 'Invalid TOTP code for disabling 2FA.'
              auditLogEntry.details.reason = 'INVALID_TOTP_DISABLE_2FA'
              const newAttempts = await this.otpService.incrementSltAttempts(sltContextToFinalize.sltJti)
              auditLogEntry.details.sltAttempts = newAttempts
              if (newAttempts >= MAX_2FA_VERIFY_ATTEMPTS) {
                auditLogEntry.details.sltFinalizedMaxAttempts = true
                throw new MaxVerificationAttemptsExceededException()
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
        } catch (sltOrVerificationError) {
          if (sltContextToFinalize) {
            await this.otpService
              .finalizeSlt(sltContextToFinalize.sltJti)
              .catch((ef) =>
                this.logger.error(
                  `Error finalizing SLT ${sltContextToFinalize?.sltJti} in disable 2FA error path: ${ef.message}`
                )
              )
            auditLogEntry.details.sltFinalizedOnError = sltContextToFinalize.sltJti
          }
          throw sltOrVerificationError
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
      auditLogEntry.details.verificationMethodUsed = 'TOTP'
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
