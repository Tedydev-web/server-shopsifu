import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import {
  TypeOfVerificationCode,
  TypeOfVerificationCodeType,
  TwoFactorMethodTypeType
} from '../constants/auth.constants'
import envConfig from 'src/shared/config'
import { EmailService } from './email.service'
import ms from 'ms'
import { v4 as uuidv4 } from 'uuid'
import { generateOTP } from 'src/routes/auth/utils/otp.utils'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma } from '@prisma/client'
import {
  InvalidOTPException,
  OTPExpiredException,
  FailedToSendOTPException,
  DeviceMismatchException,
  TooManyOTPAttemptsException,
  TooManyRequestsException,
  MaxVerificationAttemptsExceededException,
  SltContextMaxAttemptsReachedException,
  SltContextFinalizedException,
  SltCookieMissingException
} from 'src/routes/auth/auth.error'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { JwtService } from '@nestjs/jwt'
import { ApiException } from 'src/shared/exceptions/api.exception'

interface OtpData {
  code: string
  attempts: number
  createdAt: number
  userId?: number
  deviceId?: number
  metadata?: Record<string, any>
}

interface SltJwtPayload {
  jti: string
  sub: number
  pur: TypeOfVerificationCodeType
  exp: number
}

export interface SltContextData {
  userId: number
  deviceId: number
  ipAddress: string
  userAgent: string
  purpose: TypeOfVerificationCodeType
  sltJwtExp: number
  sltJwtCreatedAt: number
  finalized: '0' | '1'
  attempts: number
  metadata?: Record<string, any> & { twoFactorMethod?: TwoFactorMethodTypeType }
  email?: string
}

const OTP_SEND_COOLDOWN_SECONDS = 60
const MAX_SLT_ATTEMPTS = 5

@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name)
  private readonly MAX_OTP_ATTEMPTS = 5

  constructor(
    private readonly prismaService: PrismaService,
    private readonly emailService: EmailService,
    private readonly i18nService: I18nService,
    private readonly redisService: RedisService,
    private readonly jwtService: JwtService
  ) {}

  private _getOtpKey(type: TypeOfVerificationCodeType, identifier: string): string {
    return `${REDIS_KEY_PREFIX.OTP_CODE}${type}:${identifier}`
  }

  private _getSltContextKey(jti: string): string {
    return `${REDIS_KEY_PREFIX.SLT_CONTEXT}${jti}`
  }

  private _getSltBlacklistKey(jti: string): string {
    return `${REDIS_KEY_PREFIX.SLT_BLACKLIST_JTI}${jti}`
  }

  private _getOtpLastSentKey(identifierForCooldown: string, purpose: TypeOfVerificationCodeType): string {
    return `${REDIS_KEY_PREFIX.OTP_LAST_SENT}${identifierForCooldown}:${purpose}`
  }

  async sendOTP(
    targetEmail: string,
    type: TypeOfVerificationCodeType,
    userIdForCooldownAndOtpData?: number
  ): Promise<{ message: string }> {
    const lang = I18nContext.current()?.lang || 'en'

    if (userIdForCooldownAndOtpData) {
      const cooldownIdentifier = userIdForCooldownAndOtpData.toString()
      const cooldownKey = this._getOtpLastSentKey(cooldownIdentifier, type)
      const lastSentTimestampStr = await this.redisService.get(cooldownKey)
      if (lastSentTimestampStr) {
        const lastSentTimestamp = parseInt(lastSentTimestampStr, 10)
        if (Date.now() - lastSentTimestamp < OTP_SEND_COOLDOWN_SECONDS * 1000) {
          const cooldownMessage = await this.i18nService.translate('error.Error.Auth.Otp.CooldownActive', {
            lang,
            args: { seconds: OTP_SEND_COOLDOWN_SECONDS }
          })
          throw new TooManyRequestsException(cooldownMessage)
        }
      }
    }

    const otpKey = this._getOtpKey(type, targetEmail)
    const code = generateOTP()
    const otpTTLSeconds = Math.floor(ms(envConfig.OTP_EXPIRES_IN) / 1000)

    const otpData: OtpData = {
      code,
      attempts: 0,
      createdAt: Date.now(),
      userId: userIdForCooldownAndOtpData
    }

    await this.redisService.set(otpKey, JSON.stringify(otpData), 'EX', otpTTLSeconds)

    let title: string
    switch (type) {
      case TypeOfVerificationCode.REGISTER:
        title = this.i18nService.translate('email.OTPSubject.Register', { lang })
        break
      case TypeOfVerificationCode.RESET_PASSWORD:
        title = this.i18nService.translate('email.OTPSubject.ResetPassword', { lang })
        break
      case TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP:
        title = this.i18nService.translate('email.OTPSubject.LoginUntrustedDevice', { lang })
        break
      case TypeOfVerificationCode.VERIFY_NEW_EMAIL:
        title = this.i18nService.translate('email.Email.Subject.VerifyNewEmail', { lang })
        break
      default:
        title = this.i18nService.translate('email.OTPSubject.Default', { lang })
    }

    try {
      await this.emailService.sendOTP({ email: targetEmail, code, title })

      if (userIdForCooldownAndOtpData) {
        const cooldownIdentifier = userIdForCooldownAndOtpData.toString()
        const cooldownKey = this._getOtpLastSentKey(cooldownIdentifier, type)
        await this.redisService.set(cooldownKey, Date.now().toString(), 'EX', OTP_SEND_COOLDOWN_SECONDS)
      }
      return { message: 'Auth.Otp.SentSuccessfully' }
    } catch (error) {
      throw FailedToSendOTPException
    }
  }

  async verifyOtpOnly(
    emailToVerifyAgainst: string,
    code: string,
    type: TypeOfVerificationCodeType,
    userIdForAudit?: number,
    ip?: string,
    userAgent?: string
  ): Promise<boolean> {
    await this._verifyOtpCore(emailToVerifyAgainst, code, type, ip, userAgent, userIdForAudit)
    return true
  }

  private async _verifyOtpCore(
    identifierForOtpKey: string,
    code: string,
    type: TypeOfVerificationCodeType,
    ip?: string,
    userAgent?: string,
    userIdForAudit?: number
  ): Promise<{ otpKey: string; otpData: OtpData }> {
    const otpKey = this._getOtpKey(type, identifierForOtpKey)
    const otpDataString = await this.redisService.get(otpKey)

    const auditDetailsBase: Record<string, any> = {
      identifier: identifierForOtpKey,
      type: type,
      otpProvided: code,
      ip: ip,
      userAgent: userAgent,
      userId: userIdForAudit
    }

    if (!otpDataString) {
      throw new OTPExpiredException()
    }

    const otpData: OtpData = JSON.parse(otpDataString)

    if (type === TypeOfVerificationCode.VERIFY_NEW_EMAIL && otpData.userId !== userIdForAudit) {
      otpData.attempts += 1
      const ttl = await this.redisService.ttl(otpKey)
      if (ttl > 0) {
        await this.redisService.set(otpKey, JSON.stringify(otpData), 'EX', ttl)
      }
      throw new InvalidOTPException()
    }

    if (otpData.attempts >= this.MAX_OTP_ATTEMPTS) {
      await this.redisService.del(otpKey)
      throw new TooManyOTPAttemptsException()
    }

    if (otpData.code !== code) {
      otpData.attempts += 1
      const ttl = await this.redisService.ttl(otpKey)
      if (ttl > 0) {
        await this.redisService.set(otpKey, JSON.stringify(otpData), 'EX', ttl)
      }
      throw new InvalidOTPException()
    }

    await this.redisService.del(otpKey)

    return { otpKey, otpData }
  }

  async initiateOtpWithSltCookie(payload: {
    email: string
    userId: number
    deviceId: number
    ipAddress: string
    userAgent: string
    purpose: TypeOfVerificationCodeType
    metadata?: Record<string, any> & { twoFactorMethod?: TwoFactorMethodTypeType }
  }): Promise<string> {
    const lang = I18nContext.current()?.lang || 'en'
    const cooldownKey = this._getOtpLastSentKey(payload.userId.toString(), payload.purpose)
    const lastSentTimestampStr = await this.redisService.get(cooldownKey)

    if (lastSentTimestampStr) {
      const lastSentTimestamp = parseInt(lastSentTimestampStr, 10)
      if (Date.now() - lastSentTimestamp < OTP_SEND_COOLDOWN_SECONDS * 1000) {
        const cooldownMessage = await this.i18nService.translate('error.Error.Auth.Otp.CooldownActive', {
          lang,
          args: { seconds: OTP_SEND_COOLDOWN_SECONDS }
        })
        throw new TooManyRequestsException(cooldownMessage)
      }
    }

    const { email, userId, deviceId, ipAddress, userAgent, purpose, metadata } = payload
    const sltJti = uuidv4()
    const nowSeconds = Math.floor(Date.now() / 1000)
    const sltExpiresInSeconds = Math.floor(ms(envConfig.SLT_JWT_EXPIRES_IN) / 1000)
    const calculatedSltExp = nowSeconds + sltExpiresInSeconds

    const sltJwtPayload: Omit<SltJwtPayload, 'exp'> = {
      jti: sltJti,
      sub: userId,
      pur: purpose
    }

    const sltJwt = this.jwtService.sign(sltJwtPayload, {
      secret: envConfig.SLT_JWT_SECRET,
      expiresIn: `${sltExpiresInSeconds}s`
    })

    const sltContextDataToStore: SltContextData = {
      userId,
      deviceId,
      ipAddress,
      userAgent,
      purpose,
      sltJwtExp: calculatedSltExp,
      sltJwtCreatedAt: nowSeconds,
      finalized: '0',
      attempts: 0,
      metadata,
      email
    }

    const sltContextKey = this._getSltContextKey(sltJti)
    await this.redisService.set(sltContextKey, JSON.stringify(sltContextDataToStore), 'EX', sltExpiresInSeconds)

    if (
      purpose === TypeOfVerificationCode.REGISTER ||
      purpose === TypeOfVerificationCode.RESET_PASSWORD ||
      purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP ||
      purpose === TypeOfVerificationCode.REVERIFY_SESSION_OTP ||
      purpose === TypeOfVerificationCode.VERIFY_NEW_EMAIL
    ) {
      await this.sendOTP(email, purpose, userId)
    }

    await this.redisService.set(cooldownKey, Date.now().toString(), 'EX', OTP_SEND_COOLDOWN_SECONDS)
    return sltJwt
  }

  async verifyOTPAndCreateToken(payload: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
    userId?: number
    deviceId?: number
    metadata?: Record<string, any>
    ip?: string
    userAgent?: string
  }): Promise<string> {
    const { otpData, otpKey } = await this._verifyOtpCore(
      payload.email,
      payload.code,
      payload.type,
      payload.ip,
      payload.userAgent,
      payload.userId
    )

    const nowSeconds = Math.floor(Date.now() / 1000)
    const expiresInSeconds = Math.floor(ms(envConfig.VERIFICATION_JWT_EXPIRES_IN) / 1000)

    return `deprecated_otp_token_for_${payload.type}_${payload.email}`
  }

  async validateSltFromCookieAndGetContext(
    sltCookieValue: string,
    currentIpAddress: string,
    currentUserAgent: string,
    expectedPurpose?: TypeOfVerificationCodeType
  ): Promise<SltContextData & { sltJti: string }> {
    const auditDetails: Record<string, any> = {
      sltCookieProvided: !!sltCookieValue,
      currentIpAddress,
      currentUserAgent,
      expectedPurpose
    }

    if (!sltCookieValue) {
      throw new SltCookieMissingException()
    }

    let payload: SltJwtPayload
    try {
      payload = this.jwtService.verify<SltJwtPayload>(sltCookieValue, {
        secret: envConfig.SLT_JWT_SECRET
      })
    } catch (error) {
      auditDetails.jwtVerificationError = error.message
      if (error.name === 'TokenExpiredError') {
        throw new ApiException(HttpStatus.UNAUTHORIZED, 'SltTokenExpired', 'Error.Auth.Session.SltExpired')
      }
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'SltTokenInvalid', 'Error.Auth.Session.SltInvalid')
    }

    auditDetails.sltJti = payload.jti
    auditDetails.sltSub = payload.sub
    auditDetails.sltPurpose = payload.pur
    auditDetails.sltExp = payload.exp

    const blacklistedSlt = await this.redisService.get(this._getSltBlacklistKey(payload.jti))
    if (blacklistedSlt) {
      auditDetails.sltBlacklisted = true
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'SltTokenInvalid', 'Error.Auth.Session.SltInvalid')
    }

    const sltContextKey = this._getSltContextKey(payload.jti)
    const contextString = await this.redisService.get(sltContextKey)

    if (!contextString) {
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'SltContextNotFound', 'Error.Auth.Session.SltContextNotFound', [
        { code: 'Error.Auth.Session.SltContextNotFound', path: 'slt_token' }
      ])
    }

    const sltContext: SltContextData = JSON.parse(contextString)

    if (sltContext.finalized === '1') {
      throw new SltContextFinalizedException()
    }

    if (sltContext.attempts >= MAX_SLT_ATTEMPTS) {
      throw new SltContextMaxAttemptsReachedException()
    }

    const nowSeconds = Math.floor(Date.now() / 1000)
    if (payload.exp !== sltContext.sltJwtExp || nowSeconds >= sltContext.sltJwtExp) {
      if (nowSeconds >= sltContext.sltJwtExp) await this.redisService.del(sltContextKey)

      throw new ApiException(
        HttpStatus.UNAUTHORIZED,
        'SltTokenExpiredOrContextMismatch',
        'Error.Auth.Session.SltExpiredOrContextMismatch',
        [{ code: 'Error.Auth.Session.SltExpiredOrContextMismatch', path: 'slt_token' }]
      )
    }

    if (expectedPurpose && sltContext.purpose !== expectedPurpose) {
      await this.finalizeSlt(payload.jti)
      throw new ApiException(
        HttpStatus.BAD_REQUEST,
        'SltContextInvalidPurpose',
        'Error.Auth.SltContext.InvalidPurpose',
        [{ code: 'Error.Auth.SltContext.InvalidPurpose', path: 'slt_token' }]
      )
    }

    if (currentIpAddress !== sltContext.ipAddress) {
      await this.finalizeSlt(payload.jti)
      throw DeviceMismatchException
    }

    return { ...sltContext, sltJti: payload.jti }
  }

  async finalizeSlt(sltJti: string): Promise<void> {
    const sltContextKey = this._getSltContextKey(sltJti)
    const contextString = await this.redisService.get(sltContextKey)
    let userIdForAudit: number | undefined
    let sltPurposeForAudit: TypeOfVerificationCodeType | undefined
    let sltOriginalExp: number | undefined

    if (contextString) {
      try {
        const contextData: SltContextData = JSON.parse(contextString)
        userIdForAudit = contextData.userId
        sltPurposeForAudit = contextData.purpose
        sltOriginalExp = contextData.sltJwtExp
      } catch (e) {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }
    }

    const deletedCount = await this.redisService.del(sltContextKey)
    if (deletedCount > 0) {
      let blacklistDurationSeconds = Math.floor(ms(envConfig.SLT_JWT_EXPIRES_IN) / 1000)
      if (sltOriginalExp) {
        const nowSeconds = Math.floor(Date.now() / 1000)
        const remainingLifetime = sltOriginalExp - nowSeconds
        if (remainingLifetime > 0) {
          blacklistDurationSeconds = remainingLifetime
        } else {
          blacklistDurationSeconds = 60
        }
      }
      await this.redisService.set(this._getSltBlacklistKey(sltJti), '1', 'EX', blacklistDurationSeconds)
    }
  }

  async getSltAttempts(sltJti: string): Promise<number> {
    const sltContextKey = this._getSltContextKey(sltJti)
    const sltContextRaw = await this.redisService.get(sltContextKey)

    if (!sltContextRaw) {
      return MAX_SLT_ATTEMPTS
    }

    try {
      const sltContext = JSON.parse(sltContextRaw) as SltContextData
      if (sltContext.finalized === '1') {
        return MAX_SLT_ATTEMPTS
      }
      return sltContext.attempts
    } catch (error) {
      return MAX_SLT_ATTEMPTS
    }
  }

  async incrementSltAttempts(sltJti: string): Promise<number> {
    const sltContextKey = this._getSltContextKey(sltJti)
    const sltContextRaw = await this.redisService.get(sltContextKey)

    if (!sltContextRaw) {
      throw new ApiException(HttpStatus.BAD_REQUEST, 'SltContextInvalid', 'Error.Auth.SltContext.NotFound')
    }

    try {
      const sltContext = JSON.parse(sltContextRaw) as SltContextData

      if (sltContext.finalized === '1') {
        throw new ApiException(HttpStatus.BAD_REQUEST, 'SltContextFinalized', 'Error.Auth.SltContext.AlreadyUsed')
      }

      sltContext.attempts += 1

      const ttl = await this.redisService.ttl(sltContextKey)
      if (ttl > 0) {
        await this.redisService.set(sltContextKey, JSON.stringify(sltContext), 'EX', ttl)
      }

      return sltContext.attempts
    } catch (error) {
      if (error instanceof ApiException) throw error
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
    }
  }

  async verifySltOtpStage(
    sltCookieValue: string,
    otpCode: string,
    currentIpAddress: string,
    currentUserAgent: string
  ): Promise<void> {
    const sltContext = await this.validateSltFromCookieAndGetContext(sltCookieValue, currentIpAddress, currentUserAgent)

    if (!sltContext.email) {
      await this.finalizeSlt(sltContext.sltJti)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'SltContextError', 'Error.Auth.Session.SltInvalid')
    }

    try {
      await this.verifyOtpOnly(
        sltContext.email,
        otpCode,
        sltContext.purpose,
        sltContext.userId,
        currentIpAddress,
        currentUserAgent
      )

      sltContext.metadata = {
        ...sltContext.metadata,
        otpVerified: true,
        stageVerified: sltContext.purpose,
        otpVerifiedAt: new Date().toISOString()
      }
      sltContext.attempts = 0

      const sltContextKey = this._getSltContextKey(sltContext.sltJti)
      const ttl = await this.redisService.ttl(sltContextKey)

      if (ttl > 0) {
        await this.redisService.set(sltContextKey, JSON.stringify(sltContext), 'EX', ttl)
      } else {
        throw new ApiException(HttpStatus.CONFLICT, 'SltContextExpired', 'Error.Auth.Session.SltExpired')
      }
    } catch (error) {
      const currentAttempts = await this.incrementSltAttempts(sltContext.sltJti)

      if (currentAttempts >= MAX_SLT_ATTEMPTS) {
        await this.finalizeSlt(sltContext.sltJti)
        throw new MaxVerificationAttemptsExceededException()
      }

      if (error instanceof ApiException) throw error
      throw new InvalidOTPException()
    }
  }
}
