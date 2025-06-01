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
      otpService,
      deviceService,
      i18nService,
      redisService,
      geolocationService,
      jwtService
    )
  }

  async setupTwoFactorAuth(userId: number, deviceId: number, ipAddress: string, userAgent: string) {
    try {
      const user = await this.userRepository.findUniqueWithDetails({ id: userId })
      if (!user) {
        throw new ApiException(HttpStatus.NOT_FOUND, 'UserNotFound', 'Error.Auth.UserNotFound')
      }

      if (user.twoFactorEnabled && user.twoFactorSecret) {
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

      return {
        secret,
        uri,
        sltJwt
      }
    } catch (error) {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
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

    try {
      if (!sltCookieValue) {
        throw new SltCookieMissingException()
      }

      if (!totpCode) {
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
      } catch (error) {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'SltContextError', 'Error.Auth.Session.SltInvalid')
      }

      if (!sltContext) {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'SltContextError', 'Error.Auth.Session.SltInvalid')
      }

      if (sltContext.purpose !== TypeOfVerificationCode.SETUP_2FA) {
        throw new SltContextInvalidPurposeException()
      }

      if (sltContext.userId !== userId) {
        throw new ApiException(HttpStatus.UNAUTHORIZED, 'Error.Auth.User.Mismatch', 'Error.Auth.Access.Unauthorized')
      }

      const resultFromTransaction = await this.prismaService.$transaction(async (tx) => {
        const user = await this.userRepository.findUniqueWithDetails({ id: userId }, tx)

        if (!user) {
          throw new ApiException(HttpStatus.NOT_FOUND, 'USER_NOT_FOUND', 'Error.User.NotFound')
        }

        if (user.twoFactorEnabled) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'TWO_FACTOR_ALREADY_ENABLED', 'Error.Auth.2FA.AlreadyEnabled')
        }

        const twoFactorSecret = sltContext.metadata?.tempTwoFactorSecret as string
        if (!twoFactorSecret) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'TWO_FACTOR_SECRET_MISSING', 'Error.Auth.2FA.SetupIncomplete')
        }

        const isValidTotp = this.twoFactorService.verifyTOTP({
          email: user.email,
          secret: twoFactorSecret,
          token: totpCode
        })

        if (!isValidTotp) {
          await this.sltHelperService.handleSltAttemptIncrementAndFinalization(
            sltContext.sltJti,
            MAX_2FA_VERIFY_ATTEMPTS,
            'confirmTwoFactorSetup-invalid-totp'
          )

          throw new ApiException(HttpStatus.BAD_REQUEST, 'INVALID_TOTP_CODE', 'Error.Auth.2FA.InvalidCode')
        }

        const recoveryCodes = this.twoFactorService.generateRecoveryCodes(RECOVERY_CODES_COUNT)

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

        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) this.tokenService.clearSltCookie(res)

        return {
          recoveryCodes,
          message: await this.i18nService.translate('Auth.2FA.SetupSuccess', {
            lang: I18nContext.current()?.lang
          })
        }
      })

      return resultFromTransaction
    } catch (error) {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
    }
  }

  async disableTwoFactorAuth(
    data: DisableTwoFactorBodyType & { userId: number; userAgent?: string; ip?: string; sltCookieValue?: string }
  ) {
    let sltContextToFinalize: (SltContextData & { sltJti: string }) | null = null

    try {
      const user = await this.userRepository.findUniqueWithDetails({ id: data.userId })
      if (!user) {
        throw EmailNotFoundException
      }

      if (!user.twoFactorEnabled || !user.twoFactorSecret) {
        throw TOTPNotEnabledException
      }

      let verificationSuccessful = false

      if (data.password) {
        const isPasswordValid = await this.hashingService.compare(data.password, user.password)
        if (!isPasswordValid) {
          throw InvalidPasswordException
        }
        verificationSuccessful = true
      } else if (data.code || data.recoveryCode) {
        if (data.sltCookieValue) {
          try {
            sltContextToFinalize = await this.otpService.validateSltFromCookieAndGetContext(
              data.sltCookieValue,
              data.ip || 'N/A',
              data.userAgent || 'N/A',
              TypeOfVerificationCode.DISABLE_2FA
            )

            if (sltContextToFinalize.userId !== user.id) {
              throw new ApiException(HttpStatus.FORBIDDEN, 'AccessDenied', 'Error.Auth.AccessDenied')
            }
          } catch (sltError) {
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
          }
        }

        if (data.code) {
          const isValidTOTP = this.twoFactorService.verifyTOTP({
            email: user.email,
            secret: user.twoFactorSecret,
            token: data.code
          })
          if (!isValidTOTP) {
            if (sltContextToFinalize) {
              const newAttempts = await this.otpService.incrementSltAttempts(sltContextToFinalize.sltJti)
              if (newAttempts >= MAX_2FA_VERIFY_ATTEMPTS) {
                throw new MaxVerificationAttemptsExceededException()
              }
            }
            throw InvalidTOTPException
          }
          verificationSuccessful = true
        } else if (data.recoveryCode) {
          await this.twoFactorService.verifyRecoveryCode(user.id, data.recoveryCode, this.prismaService)
          verificationSuccessful = true
        }
      } else {
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

          if (sltContextToFinalize) {
            await this.otpService.finalizeSlt(sltContextToFinalize.sltJti)
          }
        })

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
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
          })

        return { message }
      }
    } catch (error) {
      if (sltContextToFinalize) {
        await this.otpService.finalizeSlt(sltContextToFinalize.sltJti).catch((ef) => {})
      }

      if (!(error instanceof ApiException) && !(error instanceof HttpException)) {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }
      throw error
    }
  }

  async verifyTwoFactor(
    body: TwoFactorVerifyBodyType & { userAgent: string; ip: string },
    sltContext: SltContextData & { sltJti: string },
    res?: Response
  ) {
    try {
      if (!res) {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }

      const user = await this.userRepository.findUniqueWithDetails({ id: sltContext.userId })
      if (!user || !user.role) {
        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        throw new EmailNotFoundException()
      }

      if (!user.twoFactorEnabled || !user.twoFactorSecret || !user.twoFactorMethod) {
        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        throw new TOTPNotEnabledException()
      }

      if (!body.code && !body.recoveryCode) {
        const newAttempts = await this.otpService.incrementSltAttempts(sltContext.sltJti)
        if (newAttempts >= MAX_2FA_VERIFY_ATTEMPTS) {
          await this.otpService.finalizeSlt(sltContext.sltJti)
          if (res) this.tokenService.clearSltCookie(res)
          throw new MaxVerificationAttemptsExceededException()
        }
        throw new ApiException(HttpStatus.BAD_REQUEST, 'NO_VERIFICATION_CODE', 'Error.Auth.2FA.NoVerificationCode')
      }

      let verificationMethod = ''
      if (body.code) {
        const isValid = this.twoFactorService.verifyTOTP({
          email: user.email,
          secret: user.twoFactorSecret,
          token: body.code
        })

        if (!isValid) {
          const newAttempts = await this.otpService.incrementSltAttempts(sltContext.sltJti)
          if (newAttempts >= MAX_2FA_VERIFY_ATTEMPTS) {
            await this.otpService.finalizeSlt(sltContext.sltJti)
            if (res) this.tokenService.clearSltCookie(res)
            throw new MaxVerificationAttemptsExceededException()
          }
          throw new InvalidTOTPException()
        }
        verificationMethod = 'TOTP'
      } else if (body.recoveryCode) {
        try {
          await this.twoFactorService.verifyRecoveryCode(user.id, body.recoveryCode, this.prismaService)
          verificationMethod = 'RECOVERY'
        } catch (error) {
          const newAttempts = await this.otpService.incrementSltAttempts(sltContext.sltJti)
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
        deviceToUse = await this.deviceService.findOrCreateDevice({
          userId: user.id,
          userAgent: body.userAgent,
          ip: body.ip
        })
      } else if (deviceToUse.userId !== user.id) {
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
    } catch (error) {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
    }
  }
  async regenerateRecoveryCodes(userId: number, ip?: string, userAgent?: string): Promise<{ recoveryCodes: string[] }> {
    try {
      const user = await this.userRepository.findUniqueWithDetails({ id: userId })
      if (!user || !user.role) {
        throw EmailNotFoundException
      }

      if (!user.twoFactorEnabled || user.twoFactorMethod !== TwoFactorMethodType.TOTP) {
        throw TOTPNotEnabledException
      }

      const newRecoveryCodes = this.twoFactorService.generateRecoveryCodes()
      await this.twoFactorService.saveRecoveryCodes(userId, newRecoveryCodes, this.prismaService)

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
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }

      return { recoveryCodes: newRecoveryCodes }
    } catch (error) {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
    }
  }
}
