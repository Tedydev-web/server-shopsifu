import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'
import { Response } from 'express'
import { User } from '@prisma/client'

import { SLTService } from '../../../shared/services/slt.service'
import { EmailService } from '../../../shared/services/email.service'
import { GeolocationService } from '../../../shared/services/geolocation.service'
import { UserAgentService } from '../../../shared/services/user-agent.service'

import { TwoFactorService } from './two-factor.service'
import { SessionsService } from './session.service'
import { SocialService } from './social.service'
import { PasswordService } from './password.service'

import { DeviceRepository } from 'src/shared/repositories/device.repository'
import { UserRepository } from 'src/routes/user/user.repository'
import { UserService } from 'src/routes/user/user.service'
import { CreateUserDto } from 'src/routes/user/user.dto'

import {
  COOKIE_SERVICE,
  SLT_SERVICE,
  OTP_SERVICE,
  TWO_FACTOR_SERVICE,
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  USER_AGENT_SERVICE
} from '../../../shared/constants/injection.tokens'
import { TypeOfVerificationCode, TypeOfVerificationCodeType, TwoFactorMethodType } from '../auth.constants'

import {
  ICookieService,
  SltContextData,
  IOTPService,
  ILoginFinalizationPayload,
  ILoginFinalizerService,
  LOGIN_FINALIZER_SERVICE
} from '../auth.types'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { AuthError } from '../auth.error'
import { ApiException } from '../../../shared/exceptions/api.exception'
import { GlobalError } from 'src/shared/global.error'

export interface VerificationContext {
  userId: number
  deviceId: number
  email: string
  ipAddress: string
  userAgent: string
  purpose: TypeOfVerificationCodeType
  metadata?: Record<string, any>
  rememberMe?: boolean
}

export interface VerificationResult {
  message: string
  verificationType?: 'OTP' | '2FA'
  data?: Record<string, any>
}

type PostVerificationHandler = (
  context: SltContextData & { sltJti: string },
  code: string,
  res: Response,
  sltCookieValue?: string
) => Promise<VerificationResult>

@Injectable()
export class AuthVerificationService {
  private readonly logger = new Logger(AuthVerificationService.name)

  private readonly SENSITIVE_PURPOSES: TypeOfVerificationCodeType[] = [
    TypeOfVerificationCode.DISABLE_2FA,
    TypeOfVerificationCode.REVOKE_SESSIONS,
    TypeOfVerificationCode.REVOKE_ALL_SESSIONS,
    TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT,
    TypeOfVerificationCode.REGENERATE_2FA_CODES,
    TypeOfVerificationCode.RESET_PASSWORD,
    TypeOfVerificationCode.CHANGE_PASSWORD
  ]
  private readonly VERIFICATION_ACTION_HANDLERS: Partial<Record<TypeOfVerificationCodeType, PostVerificationHandler>>

  constructor(
    private readonly configService: ConfigService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService,
    @Inject(OTP_SERVICE) private readonly otpService: IOTPService,
    @Inject(TWO_FACTOR_SERVICE) private readonly twoFactorService: TwoFactorService,
    private readonly userRepository: UserRepository,
    private readonly deviceRepository: DeviceRepository,
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(LOGIN_FINALIZER_SERVICE) private readonly loginFinalizerService: ILoginFinalizerService,
    @Inject(forwardRef(() => SessionsService)) private readonly sessionsService: SessionsService,
    @Inject(forwardRef(() => SocialService)) private readonly socialService: SocialService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService,
    private readonly passwordService: PasswordService,
    @Inject(forwardRef(() => UserService)) private readonly userService: UserService
  ) {
    this.VERIFICATION_ACTION_HANDLERS = this.initializeActionHandlers()
  }

  private initializeActionHandlers(): Partial<Record<TypeOfVerificationCodeType, PostVerificationHandler>> {
    return {
      [TypeOfVerificationCode.LOGIN]: (context, _code, res) => {
        const { userId, deviceId, ipAddress, userAgent, metadata } = context
        const rememberMe = metadata?.rememberMe === true
        return this.handleLoginVerification(userId, deviceId, rememberMe, ipAddress, userAgent, res)
      },
      [TypeOfVerificationCode.REVOKE_SESSIONS]: this.handleRevokeSessionsVerification.bind(this),
      [TypeOfVerificationCode.REVOKE_ALL_SESSIONS]: this.handleRevokeAllSessionsVerification.bind(this),
      [TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT]: this.handleUnlinkGoogleAccountVerification.bind(this),
      [TypeOfVerificationCode.DISABLE_2FA]: this.handleDisable2FAVerification.bind(this),
      [TypeOfVerificationCode.SETUP_2FA]: this.handleSetup2FAVerification.bind(this),
      [TypeOfVerificationCode.REGISTER]: this.handleRegistrationOtpVerified.bind(this),
      [TypeOfVerificationCode.CREATE_USER]: this.handleCreateUserVerification.bind(this),
      [TypeOfVerificationCode.REGENERATE_2FA_CODES]: this.handleRegenerate2FACodesVerification.bind(this),
      [TypeOfVerificationCode.RESET_PASSWORD]: this.handleResetPasswordVerification.bind(this),
      [TypeOfVerificationCode.CHANGE_PASSWORD]: this.handleChangePasswordVerification.bind(this)
    }
  }

  async initiateVerification(context: VerificationContext, res: Response): Promise<VerificationResult> {
    const { userId, purpose } = context

    if (purpose === TypeOfVerificationCode.REGISTER || purpose === TypeOfVerificationCode.CREATE_USER) {
      return this.handleRegistrationInitiation(context, res)
    }

    if (purpose === TypeOfVerificationCode.SETUP_2FA) {
      return this.handleSetup2FAInitiation(context, res)
    }

    const user = await this.userRepository.findById(userId)
    if (!user) {
      throw AuthError.EmailNotFound()
    }

    if (this.SENSITIVE_PURPOSES.includes(purpose) || purpose === TypeOfVerificationCode.LOGIN) {
      return this.handleLoginOrSensitiveActionInitiation(context, res, user)
    }

    return {
      message: 'global.general.success.default'
    }
  }

  private async handleSetup2FAInitiation(context: VerificationContext, res: Response): Promise<VerificationResult> {
    const sltToken = await this.sltService.createAndStoreSltToken(context)
    this.cookieService.setSltCookie(res, sltToken, context.purpose)
    const result = await this.twoFactorService.generateSetupDetails(context.userId)

    const sltJti = this.sltService.extractJtiFromToken(sltToken)
    await this.sltService.updateSltContext(sltJti, {
      metadata: { ...context.metadata, twoFactorSecret: result.data.secret }
    })

    return {
      message: 'auth.success.2fa.setupInitiated',
      data: {
        qrCode: result.data.qrCode,
        secret: result.data.secret
      }
    }
  }

  private handleRegistrationInitiation(context: VerificationContext, res: Response): Promise<VerificationResult> {
    return this.initiateOtpFlow(context, res)
  }

  private async handleLoginOrSensitiveActionInitiation(
    context: VerificationContext,
    res: Response,
    user: User
  ): Promise<VerificationResult> {
    const { purpose } = context

    if (this.SENSITIVE_PURPOSES.includes(purpose)) {
      return this.initiateOtpOr2faFlow(context, res, user)
    }

    if (purpose === TypeOfVerificationCode.LOGIN) {
      return this.handleLoginSpecificLogic(context, res, user)
    }

    return { message: 'global.general.success.default' }
  }

  private async handleLoginSpecificLogic(
    context: VerificationContext,
    res: Response,
    user: User
  ): Promise<VerificationResult> {
    const { userId, deviceId, metadata, ipAddress, userAgent, rememberMe } = context
    const isDeviceTrusted = await this.deviceRepository.isDeviceTrustValid(deviceId)
    const forceVerification = metadata?.forceVerification === true

    if (forceVerification || !isDeviceTrusted) {
      return this.initiateOtpOr2faFlow(context, res, user)
    }

    return this.handleLoginVerification(userId, deviceId, rememberMe ?? false, ipAddress, userAgent, res)
  }

  private async initiateOtpOr2faFlow(
    context: VerificationContext,
    res: Response,
    user: User
  ): Promise<VerificationResult> {
    const { purpose } = context

    if (user.twoFactorEnabled) {
      const sltPayload = {
        ...context,
        metadata: {
          ...context.metadata,
          twoFactorEnabled: true,
          twoFactorSecret: user.twoFactorSecret,
          twoFactorMethod: user.twoFactorMethod || 'TOTP'
        }
      }

      const sltToken = await this.sltService.createAndStoreSltToken(sltPayload)
      this.cookieService.setSltCookie(res, sltToken, purpose)
      return {
        message: 'auth.success.login.2faRequired',
        verificationType: '2FA'
      }
    }

    return this.initiateOtpFlow(context, res)
  }

  async reInitiateVerification(
    sltCookieValue: string,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(sltCookieValue, ipAddress, userAgent)

    if (sltContext.metadata?.twoFactorMethod) {
      return {
        message: 'auth.success.login.2faRequired',
        verificationType: '2FA'
      }
    }

    if (!sltContext.email) {
      throw AuthError.EmailMissingInSltContext()
    }

    await this.otpService.sendOTP(sltContext.email, sltContext.purpose, sltContext)
    const newSltToken = await this.sltService.createAndStoreSltToken(sltContext)
    this.cookieService.setSltCookie(res, newSltToken, sltContext.purpose)

    return {
      message: 'auth.success.otp.resent',
      verificationType: 'OTP'
    }
  }

  async verifyCode(
    sltCookieValue: string,
    code: string,
    ipAddress: string,
    userAgent: string,
    res: Response,
    additionalMetadata?: Record<string, any>
  ): Promise<VerificationResult> {
    try {
      return await this._verificationFlow(sltCookieValue, code, ipAddress, userAgent, res, additionalMetadata)
    } catch (error) {
      if (error instanceof ApiException) {
        const terminalSltErrorCodes = [
          'AUTH_SLT_EXPIRED',
          'AUTH_SLT_INVALID',
          'AUTH_SLT_ALREADY_USED',
          'AUTH_SLT_MAX_ATTEMPTS_EXCEEDED',
          'AUTH_SLT_INVALID_PURPOSE',
          'AUTH_EMAIL_MISSING_IN_CONTEXT'
        ]

        if (terminalSltErrorCodes.includes(error.code)) {
          this.cookieService.clearSltCookie(res)
        }

        throw error
      }

      this.cookieService.clearSltCookie(res)
      throw GlobalError.InternalServerError()
    }
  }

  private async _verificationFlow(
    sltCookieValue: string,
    code: string,
    ipAddress: string,
    userAgent: string,
    res: Response,
    additionalMetadata?: Record<string, any>
  ): Promise<VerificationResult> {
    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(sltCookieValue, ipAddress, userAgent)

    if (additionalMetadata) {
      sltContext.metadata = { ...sltContext.metadata, ...additionalMetadata }
    }

    await this.verifyAuthenticationCode(sltContext, code)
    const result = await this.handlePostVerificationActions(sltContext, code, res, sltCookieValue)

    if (!this.shouldKeepSltCookie(sltContext.purpose)) {
      this.cookieService.clearSltCookie(res)
    }

    return result
  }

  private shouldKeepSltCookie(purpose: TypeOfVerificationCodeType): boolean {
    return purpose === TypeOfVerificationCode.REGISTER || purpose === TypeOfVerificationCode.RESET_PASSWORD
  }

  private async verifyAuthenticationCode(sltContext: SltContextData & { sltJti: string }, code: string): Promise<void> {
    const { userId, purpose, metadata } = sltContext
    const { twoFactorMethod, totpSecret, twoFactorSecret, twoFactorEnabled, requestMethod } = metadata || {}

    try {
      const has2FASecret = totpSecret || twoFactorSecret
      const isUserHas2FA = twoFactorEnabled || has2FASecret
      const isSetup2FA = purpose === TypeOfVerificationCode.SETUP_2FA
      const should2FA = (purpose === TypeOfVerificationCode.LOGIN && isUserHas2FA) || (isSetup2FA && has2FASecret)

      if (should2FA) {
        const effectiveMethod = requestMethod || twoFactorMethod

        await this.verifyWith2FA(code, userId, has2FASecret, effectiveMethod, purpose)
      } else {
        await this.verifyWithOtp(code, sltContext)
      }
    } catch (error) {
      const newAttemptCount = await this.sltService.incrementSltAttempts(sltContext.sltJti)
      if (newAttemptCount >= 5 && (error.code === 'AUTH_INVALID_OTP' || error.code === 'AUTH_2FA_INVALID_TOTP')) {
        throw AuthError.VerificationSessionExpired()
      }
      throw error
    }
  }

  private async verifyWithOtp(code: string, sltContext: SltContextData): Promise<void> {
    if (!sltContext.email) {
      throw AuthError.EmailMissingInSltContext()
    }
    await this.otpService.verifyOTP(sltContext.email, code, sltContext.purpose)
  }

  private async verifyWith2FA(
    code: string,
    userId: number,
    totpSecret: string | undefined,
    method?: string,
    purpose?: TypeOfVerificationCodeType
  ): Promise<void> {
    const effectiveMethod: TwoFactorMethodType =
      method && Object.values(TwoFactorMethodType).includes(method as TwoFactorMethodType)
        ? (method as TwoFactorMethodType)
        : TwoFactorMethodType.TOTP

    const isValid = await this.twoFactorService.verifyCode(code, {
      userId: userId,
      method: effectiveMethod,
      secret: totpSecret
    })

    if (!isValid) {
      throw AuthError.InvalidOTP()
    }
  }

  private async handlePostVerificationActions(
    sltContext: SltContextData & { sltJti: string },
    code: string,
    res: Response,
    sltCookieValue?: string
  ): Promise<VerificationResult> {
    const { purpose } = sltContext

    if (!this.shouldKeepSltCookie(sltContext.purpose)) {
      await this.sltService.finalizeSlt(sltContext.sltJti)
    }

    const handler = this.VERIFICATION_ACTION_HANDLERS[purpose]
    if (handler) {
      return handler(sltContext, code, res, sltCookieValue)
    }

    await this.sltService.finalizeSlt(sltContext.sltJti)
    return { message: 'auth.success.otp.verified' }
  }

  private async handleLoginVerification(
    userId: number,
    deviceId: number,
    rememberMe: boolean,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<VerificationResult> {
    if (!this.loginFinalizerService) {
      throw AuthError.ServiceNotAvailable('LoginFinalizerService')
    }

    const loginPayload: ILoginFinalizationPayload = {
      userId,
      deviceId,
      rememberMe,
      ipAddress,
      userAgent
    }

    const loginResult = await this.loginFinalizerService.finalizeLoginAfterVerification(loginPayload, res)

    if (rememberMe) {
      await this.deviceRepository.updateDeviceTrustStatus(deviceId, true)
    }

    return loginResult
  }

  private async handleRevokeSessionsVerification(
    context: SltContextData,
    code: string,
    res: Response
  ): Promise<VerificationResult> {
    const { userId, metadata, ipAddress, userAgent, email } = context
    const { sessionIds, deviceIds, excludeCurrentSession, currentSessionId, currentDeviceId } = metadata || {}

    if (!sessionIds && !deviceIds) {
      throw GlobalError.BadRequest('auth.error.invalidRevokeParams')
    }

    const revokeResult = await this.sessionsService.revokeItems(
      userId,
      { sessionIds, deviceIds, excludeCurrentSession },
      { sessionId: currentSessionId, deviceId: currentDeviceId },
      res
    )

    await this._sendSessionRevocationEmail(email, userId, ipAddress, userAgent)

    return {
      message: revokeResult.message || 'auth.success.session.revoked',
      data: {
        revokedSessionsCount: revokeResult.data.revokedSessionsCount,
        untrustedDevicesCount: revokeResult.data.untrustedDevicesCount,
        willCauseLogout: revokeResult.data.willCauseLogout,
        warningMessage: revokeResult.data.warningMessage,
        requiresConfirmation: revokeResult.data.requiresConfirmation
      }
    }
  }

  private async handleRevokeAllSessionsVerification(
    context: SltContextData,
    code: string,
    res: Response
  ): Promise<VerificationResult> {
    const { userId, metadata, ipAddress, userAgent, email } = context
    const { excludeCurrentSession, currentSessionId, currentDeviceId } = metadata || {}

    const revokeResult = await this.sessionsService.revokeItems(
      userId,
      { revokeAllUserSessions: true, excludeCurrentSession },
      { sessionId: currentSessionId, deviceId: currentDeviceId },
      res
    )

    await this._sendSessionRevocationEmail(email, userId, ipAddress, userAgent)

    return {
      message: revokeResult.message || 'auth.success.session.allRevoked',
      data: {
        revokedSessionsCount: revokeResult.data.revokedSessionsCount,
        untrustedDevicesCount: revokeResult.data.untrustedDevicesCount,
        willCauseLogout: revokeResult.data.willCauseLogout,
        warningMessage: revokeResult.data.warningMessage,
        requiresConfirmation: revokeResult.data.requiresConfirmation
      }
    }
  }

  private async handleUnlinkGoogleAccountVerification(context: SltContextData): Promise<VerificationResult> {
    const result = await this.socialService.unlinkGoogleAccount(context.userId)
    return { message: result.message }
  }

  private async handleDisable2FAVerification(context: SltContextData): Promise<VerificationResult> {
    const result = await this.twoFactorService.disableVerificationAfterConfirm(context.userId)
    return { message: result.message }
  }

  private async handleSetup2FAVerification(context: SltContextData, code: string): Promise<VerificationResult> {
    const { twoFactorSecret } = context.metadata || {}

    if (!twoFactorSecret) {
      throw GlobalError.InternalServerError('auth.error.twoFactorSetupMissingSecret')
    }

    const result = await this.twoFactorService.confirmTwoFactorSetup(
      context.userId,
      code,
      twoFactorSecret,
      context.ipAddress,
      context.userAgent
    )

    return {
      message: 'auth.success.2fa.setupConfirmed',
      data: { recoveryCodes: result.data.recoveryCodes }
    }
  }

  private async handleRegistrationOtpVerified(
    context: SltContextData & { sltJti: string }
  ): Promise<VerificationResult> {
    await this.sltService.updateSltContext(context.sltJti, {
      metadata: { ...context.metadata, otpVerified: 'true' }
    })
    return {
      message: 'auth.success.otp.verified',
      verificationType: 'OTP'
    }
  }

  private async handleRegenerate2FACodesVerification(
    context: SltContextData,
    code: string
  ): Promise<VerificationResult> {
    const { userId, ipAddress, userAgent, metadata } = context
    const result = await this.twoFactorService.regenerateRecoveryCodes(
      userId,
      code,
      metadata?.twoFactorMethod,
      ipAddress,
      userAgent
    )
    return {
      message: 'auth.success.2fa.recoveryCodesRegenerated',
      data: { recoveryCodes: result.data.recoveryCodes }
    }
  }

  private async handleResetPasswordVerification(
    context: SltContextData & { sltJti: string }
  ): Promise<VerificationResult> {
    await this.sltService.updateSltContext(context.sltJti, {
      metadata: { ...context.metadata, otpVerified: 'true' }
    })
    return {
      message: 'auth.success.otp.verifiedResetPassword'
    }
  }

  private async handleChangePasswordVerification(context: SltContextData): Promise<VerificationResult> {
    const { newPassword, revokeAllSessions } = context.metadata || {}

    await this.passwordService.performPasswordUpdate({
      userId: context.userId,
      newPassword: newPassword,
      revokeAllSessions: revokeAllSessions,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      currentSessionId: context.metadata?.currentSessionId,
      isPasswordAlreadyHashed: true
    })

    return { message: 'auth.success.password.changeSuccess' }
  }

  private async handleCreateUserVerification(context: SltContextData): Promise<VerificationResult> {
    const { metadata } = context

    if (!metadata) {
      throw AuthError.InternalServerError('Missing user creation data')
    }

    const createUserDto: CreateUserDto = {
      email: metadata.email,
      password: metadata.password,
      roleId: metadata.roleId,
      firstName: metadata.firstName,
      lastName: metadata.lastName,
      username: metadata.username,
      phoneNumber: metadata.phoneNumber,
      bio: metadata.bio,
      avatar: metadata.avatar,
      countryCode: metadata.countryCode || 'VN',
      isEmailVerified: metadata.isEmailVerified || false,
      requireEmailVerification: metadata.requireEmailVerification || true
    }

    const result = await this.userService.createFromOtpVerification(createUserDto)

    const userData = result.data as any

    return {
      message: result.message,
      data: {
        user: {
          id: userData.id,
          email: userData.email,
          role: userData.role?.name,
          username: userData.userProfile?.username,
          firstName: userData.userProfile?.firstName,
          lastName: userData.userProfile?.lastName
        }
      }
    }
  }

  private async initiateOtpFlow(context: VerificationContext, res: Response): Promise<VerificationResult> {
    const { email, purpose, metadata, ipAddress, userAgent } = context
    const sltToken = await this.sltService.createAndStoreSltToken(context)

    this.cookieService.setSltCookie(res, sltToken, purpose)
    await this.otpService.sendOTP(email, purpose, { ...metadata, ipAddress, userAgent })

    return {
      message: 'auth.success.otp.sent',
      verificationType: 'OTP'
    }
  }

  private async _sendSessionRevocationEmail(
    email: string,
    userId: number,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    const user = await this.userRepository.findByIdWithDetails(userId)
    if (!user?.email) {
      return
    }

    const userAgentInfo = this.userAgentService.parse(userAgent)
    const locationInfo = ipAddress ? await this.geolocationService.getLocationFromIP(ipAddress) : null

    await this.emailService.sendSessionRevokeEmail(user.email, {
      userName: user.userProfile?.username ?? user.email.split('@')[0],
      details: [
        {
          label: 'email.Email.common.details.ipAddress',
          value: ipAddress ?? 'N/A'
        },
        {
          label: 'email.Email.common.details.location',
          value: locationInfo?.display ?? 'N/A'
        },
        {
          label: 'email.Email.common.details.device',
          value: `${userAgentInfo.browser || 'Unknown'} on ${userAgentInfo.os || 'Unknown'}`
        }
      ]
    })
  }
}
