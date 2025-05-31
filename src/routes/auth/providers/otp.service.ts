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
import { AuditLogService, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
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
    private readonly jwtService: JwtService,
    private readonly auditLogService: AuditLogService
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
          this.logger.warn(`OTP send cooldown active for identifier ${cooldownIdentifier}, type ${type}.`)
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
    this.logger.debug(
      `OTP for ${type} for target ${targetEmail} (user: ${userIdForCooldownAndOtpData}) stored. Key: ${otpKey}`
    )

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
      this.auditLogService.recordAsync({
        userEmail: targetEmail,
        userId: userIdForCooldownAndOtpData,
        action: 'OTP_SENT',
        status: AuditLogStatus.SUCCESS,
        details: { type, emailSentTo: targetEmail, forUserId: userIdForCooldownAndOtpData } as Prisma.JsonObject
      })

      if (userIdForCooldownAndOtpData) {
        const cooldownIdentifier = userIdForCooldownAndOtpData.toString()
        const cooldownKey = this._getOtpLastSentKey(cooldownIdentifier, type)
        await this.redisService.set(cooldownKey, Date.now().toString(), 'EX', OTP_SEND_COOLDOWN_SECONDS)
      }
      return { message: 'Auth.Otp.SentSuccessfully' }
    } catch (error) {
      this.logger.error(
        `Failed to send OTP to ${targetEmail} for type ${type} (user: ${userIdForCooldownAndOtpData})`,
        error
      )
      this.auditLogService.recordAsync({
        userEmail: targetEmail,
        userId: userIdForCooldownAndOtpData,
        action: 'OTP_SEND_FAILED',
        status: AuditLogStatus.FAILURE,
        errorMessage: error.message,
        details: { type, forUserId: userIdForCooldownAndOtpData } as Prisma.JsonObject
      })
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
      this.logger.warn(`OTP verification failed: No OTP data found for key ${otpKey}`)
      this.auditLogService.recordAsync({
        userEmail: type === TypeOfVerificationCode.VERIFY_NEW_EMAIL ? identifierForOtpKey : undefined,
        userId: userIdForAudit,
        action: 'OTP_VERIFY_FAIL',
        status: AuditLogStatus.FAILURE,
        errorMessage: 'OTP_EXPIRED_OR_NOT_FOUND',
        details: auditDetailsBase as Prisma.JsonObject
      })
      throw new OTPExpiredException()
    }

    const otpData: OtpData = JSON.parse(otpDataString)

    if (type === TypeOfVerificationCode.VERIFY_NEW_EMAIL && otpData.userId !== userIdForAudit) {
      this.logger.warn(
        `OTP verification failed for ${identifierForOtpKey} (type ${type}): OTP data user ID (${otpData.userId}) does not match audit user ID (${userIdForAudit}). Key: ${otpKey}`
      )
      otpData.attempts += 1
      const ttl = await this.redisService.ttl(otpKey)
      if (ttl > 0) {
        await this.redisService.set(otpKey, JSON.stringify(otpData), 'EX', ttl)
      }
      this.auditLogService.recordAsync({
        userEmail: identifierForOtpKey,
        userId: userIdForAudit,
        action: 'OTP_VERIFY_FAIL',
        status: AuditLogStatus.FAILURE,
        errorMessage: 'OTP_USER_MISMATCH',
        details: { ...auditDetailsBase, otpUserId: otpData.userId, attempts: otpData.attempts } as Prisma.JsonObject
      })
      throw new InvalidOTPException()
    }

    if (otpData.attempts >= this.MAX_OTP_ATTEMPTS) {
      this.logger.warn(`OTP verification failed: Max attempts reached for key ${otpKey}`)
      await this.redisService.del(otpKey)
      this.auditLogService.recordAsync({
        userEmail: type === TypeOfVerificationCode.VERIFY_NEW_EMAIL ? identifierForOtpKey : undefined,
        userId: userIdForAudit,
        action: 'OTP_VERIFY_FAIL',
        status: AuditLogStatus.FAILURE,
        errorMessage: 'MAX_OTP_ATTEMPTS_REACHED',
        details: { ...auditDetailsBase, attempts: otpData.attempts } as Prisma.JsonObject
      })
      throw new TooManyOTPAttemptsException()
    }

    if (otpData.code !== code) {
      otpData.attempts += 1
      const ttl = await this.redisService.ttl(otpKey)
      if (ttl > 0) {
        await this.redisService.set(otpKey, JSON.stringify(otpData), 'EX', ttl)
      }
      this.logger.warn(
        `OTP verification failed: Invalid code for key ${otpKey}. Attempt ${otpData.attempts}/${this.MAX_OTP_ATTEMPTS}`
      )
      this.auditLogService.recordAsync({
        userEmail: type === TypeOfVerificationCode.VERIFY_NEW_EMAIL ? identifierForOtpKey : undefined,
        userId: userIdForAudit,
        action: 'OTP_VERIFY_FAIL',
        status: AuditLogStatus.FAILURE,
        errorMessage: 'INVALID_OTP_CODE',
        details: { ...auditDetailsBase, attempts: otpData.attempts } as Prisma.JsonObject
      })
      throw new InvalidOTPException()
    }

    await this.redisService.del(otpKey)
    this.logger.debug(`OTP for key ${otpKey} verified and deleted from Redis.`)

    this.auditLogService.recordAsync({
      userEmail: type === TypeOfVerificationCode.VERIFY_NEW_EMAIL ? identifierForOtpKey : undefined,
      userId: userIdForAudit,
      action: 'OTP_VERIFY_ONLY_SUCCESS',
      status: AuditLogStatus.SUCCESS,
      details: { ...auditDetailsBase, type } as Prisma.JsonObject
    })
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
        this.logger.warn(`SLT OTP send cooldown active for user ${payload.userId}, purpose ${payload.purpose}.`)
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
    this.logger.debug(`SLT context for JTI ${sltJti} stored in Redis. Key: ${sltContextKey}`)

    if (
      purpose === TypeOfVerificationCode.REGISTER ||
      purpose === TypeOfVerificationCode.RESET_PASSWORD ||
      purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP ||
      purpose === TypeOfVerificationCode.REVERIFY_SESSION_OTP ||
      purpose === TypeOfVerificationCode.VERIFY_NEW_EMAIL
    ) {
      await this.sendOTP(email, purpose, userId)
      this.logger.debug(`OTP sent for SLT purpose: ${purpose} to email: ${email} for user: ${userId}`)
    }

    this.auditLogService.recordAsync({
      userId,
      action: 'SLT_INITIATED',
      status: AuditLogStatus.SUCCESS,
      ipAddress,
      userAgent,
      details: {
        sltJti,
        purpose,
        deviceId,
        targetEmail: email,
        metadata
      } as Prisma.JsonObject
    })

    await this.redisService.set(cooldownKey, Date.now().toString(), 'EX', OTP_SEND_COOLDOWN_SECONDS)
    this.logger.debug(
      `SLT OTP send cooldown set for user ${payload.userId}, purpose ${payload.purpose}. Key: ${cooldownKey}`
    )
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

    this.auditLogService.recordAsync({
      userEmail: payload.email,
      action: 'OTP_VERIFY_SUCCESS_JWT_CREATED',
      userId: payload.userId,
      status: AuditLogStatus.SUCCESS,
      details: { ...otpData, verifiedOtpKey: otpKey } as Prisma.JsonObject
    })

    this.logger.warn(
      'verifyOTPAndCreateToken called, but JWT creation part is deprecated and removed. Returning placeholder for otpToken.'
    )
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
      this.logger.warn('SLT cookie value is missing.')
      this.auditLogService.recordAsync({
        action: 'SLT_VALIDATE_FAIL',
        status: AuditLogStatus.FAILURE,
        errorMessage: 'SLT_COOKIE_MISSING',
        details: auditDetails as Prisma.JsonObject
      })
      throw new SltCookieMissingException()
    }

    let payload: SltJwtPayload
    try {
      payload = this.jwtService.verify<SltJwtPayload>(sltCookieValue, {
        secret: envConfig.SLT_JWT_SECRET
      })
    } catch (error) {
      this.logger.warn(`SLT JWT verification failed: ${error.message}`)
      auditDetails.jwtVerificationError = error.message
      this.auditLogService.recordAsync({
        action: 'SLT_VALIDATE_FAIL',
        status: AuditLogStatus.FAILURE,
        errorMessage: 'SLT_JWT_INVALID_OR_EXPIRED',
        details: auditDetails as Prisma.JsonObject
      })
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
      this.logger.warn(`SLT JTI ${payload.jti} is blacklisted.`)
      auditDetails.sltBlacklisted = true
      this.auditLogService.recordAsync({
        userId: payload.sub,
        action: 'SLT_VALIDATE_FAIL',
        status: AuditLogStatus.FAILURE,
        errorMessage: 'SLT_JTI_BLACKLISTED',
        details: auditDetails as Prisma.JsonObject
      })
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'SltTokenInvalid', 'Error.Auth.Session.SltInvalid')
    }

    const sltContextKey = this._getSltContextKey(payload.jti)
    const contextString = await this.redisService.get(sltContextKey)

    if (!contextString) {
      this.logger.warn(`SLT context not found in Redis for JTI ${payload.jti}. Key: ${sltContextKey}.`)
      this.auditLogService.recordAsync({
        userId: payload.sub,
        action: 'SLT_VALIDATION_FAIL',
        status: AuditLogStatus.FAILURE,
        ipAddress: currentIpAddress,
        userAgent: currentUserAgent,
        errorMessage: 'SLT_CONTEXT_NOT_FOUND_OR_EXPIRED_IN_REDIS',
        details: auditDetails as Prisma.JsonObject
      })
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'SltContextNotFound', 'Error.Auth.Session.SltContextNotFound', [
        { code: 'Error.Auth.Session.SltContextNotFound', path: 'slt_token' }
      ])
    }

    const sltContext: SltContextData = JSON.parse(contextString)

    if (sltContext.finalized === '1') {
      this.logger.warn(`Attempt to use an already finalized SLT context for JTI ${payload.jti}.`)
      this.auditLogService.recordAsync({
        userId: payload.sub,
        action: 'SLT_VALIDATION_FAIL',
        status: AuditLogStatus.FAILURE,
        ipAddress: currentIpAddress,
        userAgent: currentUserAgent,
        errorMessage: 'SLT_CONTEXT_ALREADY_FINALIZED',
        details: auditDetails as Prisma.JsonObject
      })
      throw new SltContextFinalizedException()
    }

    if (sltContext.attempts >= MAX_SLT_ATTEMPTS) {
      this.logger.warn(
        `SLT JTI ${payload.jti} has already reached max attempts (${sltContext.attempts}/${MAX_SLT_ATTEMPTS}) upon validation.`
      )
      this.auditLogService.recordAsync({
        userId: payload.sub,
        action: 'SLT_VALIDATE_FAIL_MAX_ATTEMPTS_PRE_CHECK',
        status: AuditLogStatus.FAILURE,
        ipAddress: currentIpAddress,
        userAgent: currentUserAgent,
        errorMessage: 'SLT_CONTEXT_MAX_ATTEMPTS_REACHED_ON_VALIDATE',
        details: {
          ...auditDetails,
          currentAttempts: sltContext.attempts,
          maxAttempts: MAX_SLT_ATTEMPTS
        } as Prisma.JsonObject
      })
      throw new SltContextMaxAttemptsReachedException()
    }

    const nowSeconds = Math.floor(Date.now() / 1000)
    if (payload.exp !== sltContext.sltJwtExp || nowSeconds >= sltContext.sltJwtExp) {
      this.logger.warn(
        `SLT JWT/Context expiry mismatch or SLT expired for JTI ${payload.jti}. JWT exp: ${payload.exp}, Context exp: ${sltContext.sltJwtExp}, Now: ${nowSeconds}`
      )
      if (nowSeconds >= sltContext.sltJwtExp) await this.redisService.del(sltContextKey)
      this.auditLogService.recordAsync({
        userId: payload.sub,
        action: 'SLT_VALIDATION_FAIL',
        status: AuditLogStatus.FAILURE,
        ipAddress: currentIpAddress,
        userAgent: currentUserAgent,
        errorMessage: 'SLT_EXPIRED_OR_EXPIRY_MISMATCH',
        details: {
          ...auditDetails,
          jwtExp: payload.exp,
          contextExp: sltContext.sltJwtExp,
          actualPurposeInContext: sltContext.purpose
        } as Prisma.JsonObject
      })
      throw new ApiException(
        HttpStatus.UNAUTHORIZED,
        'SltTokenExpiredOrContextMismatch',
        'Error.Auth.Session.SltExpiredOrContextMismatch',
        [{ code: 'Error.Auth.Session.SltExpiredOrContextMismatch', path: 'slt_token' }]
      )
    }

    if (expectedPurpose && sltContext.purpose !== expectedPurpose) {
      this.logger.warn(
        `SLT JTI ${payload.jti}: Purpose mismatch. Expected: ${expectedPurpose}, Actual: ${sltContext.purpose}.`
      )
      this.auditLogService.recordAsync({
        userId: payload.sub,
        action: 'SLT_VALIDATE_FAIL_PURPOSE_MISMATCH',
        status: AuditLogStatus.FAILURE,
        ipAddress: currentIpAddress,
        userAgent: currentUserAgent,
        errorMessage: 'SLT_CONTEXT_PURPOSE_MISMATCH',
        details: {
          ...auditDetails,
          expectedPurpose,
          actualPurpose: sltContext.purpose
        } as Prisma.JsonObject
      })
      await this.finalizeSlt(payload.jti)
      throw new ApiException(
        HttpStatus.BAD_REQUEST,
        'SltContextInvalidPurpose',
        'Error.Auth.SltContext.InvalidPurpose',
        [{ code: 'Error.Auth.SltContext.InvalidPurpose', path: 'slt_token' }]
      )
    }

    if (currentIpAddress !== sltContext.ipAddress) {
      this.logger.warn(
        `SLT JTI ${payload.jti}: IP address mismatch. Context IP: ${sltContext.ipAddress}, Current IP: ${currentIpAddress}.`
      )
      this.auditLogService.recordAsync({
        action: 'SLT_CONTEXT_VALIDATION_FAIL',
        userId: sltContext.userId,
        userEmail: sltContext.email,
        ipAddress: currentIpAddress,
        userAgent: currentUserAgent,
        status: AuditLogStatus.FAILURE,
        errorMessage: 'SLT_IP_MISMATCH',
        details: {
          sltJti: payload.jti,
          expectedIp: sltContext.ipAddress,
          actualIp: currentIpAddress,
          expectedUserAgent: sltContext.userAgent,
          actualUserAgent: currentUserAgent
        } as Prisma.JsonObject
      })
      await this.finalizeSlt(payload.jti)
      throw DeviceMismatchException
    }

    this.auditLogService.recordAsync({
      userId: payload.sub,
      userEmail: sltContext.email,
      action: 'SLT_VALIDATION_SUCCESS',
      status: AuditLogStatus.SUCCESS,
      ipAddress: currentIpAddress,
      userAgent: currentUserAgent,
      details: {
        ...auditDetails,
        contextUserId: sltContext.userId,
        contextDeviceId: sltContext.deviceId,
        actualPurposeInContext: sltContext.purpose
      } as Prisma.JsonObject
    })
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
        this.logger.error(`Failed to parse SLT context for JTI ${sltJti} during finalization: ${e.message}`)
      }
    }

    const deletedCount = await this.redisService.del(sltContextKey)
    if (deletedCount > 0) {
      this.logger.debug(`SLT context for JTI ${sltJti} finalized and deleted from Redis.`)

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
      this.logger.debug(`SLT JTI ${sltJti} blacklisted for ${blacklistDurationSeconds} seconds.`)

      this.auditLogService.recordAsync({
        userId: userIdForAudit,
        action: 'SLT_FINALIZED',
        status: AuditLogStatus.SUCCESS,
        details: {
          sltJti,
          purpose: sltPurposeForAudit,
          contextDeleted: true,
          jtiBlacklisted: true
        } as Prisma.JsonObject
      })
    } else {
      this.logger.warn(
        `Attempted to finalize SLT JTI ${sltJti}, but no context was found in Redis. It might have expired or been finalized already.`
      )
      this.auditLogService.recordAsync({
        userId: userIdForAudit,
        action: 'SLT_FINALIZE_NO_CONTEXT',
        status: AuditLogStatus.FAILURE,
        details: {
          sltJti,
          purpose: sltPurposeForAudit,
          contextFound: false,
          note: 'Context might have expired or been finalized already.'
        } as Prisma.JsonObject
      })
    }
  }

  async getSltAttempts(sltJti: string): Promise<number> {
    const sltContextKey = this._getSltContextKey(sltJti)
    const sltContextRaw = await this.redisService.get(sltContextKey)

    if (!sltContextRaw) {
      this.logger.warn(
        `SLT context for JTI ${sltJti} not found in Redis during getSltAttempts. Returning max attempts.`
      )
      return MAX_SLT_ATTEMPTS
    }

    try {
      const sltContext = JSON.parse(sltContextRaw) as SltContextData
      if (sltContext.finalized === '1') {
        this.logger.log(`SLT context for JTI ${sltJti} is already finalized. Returning max attempts.`)
        return MAX_SLT_ATTEMPTS
      }
      return sltContext.attempts
    } catch (error) {
      this.logger.error(
        `Error parsing SLT context for JTI ${sltJti} during getSltAttempts: ${error.message}`,
        error.stack
      )
      return MAX_SLT_ATTEMPTS
    }
  }

  async incrementSltAttempts(sltJti: string): Promise<number> {
    const sltContextKey = this._getSltContextKey(sltJti)
    const sltContextRaw = await this.redisService.get(sltContextKey)

    if (!sltContextRaw) {
      this.logger.warn(`SLT context for JTI ${sltJti} not found in Redis during incrementSltAttempts.`)
      throw new ApiException(HttpStatus.BAD_REQUEST, 'SltContextInvalid', 'Error.Auth.SltContext.NotFound')
    }

    try {
      const sltContext = JSON.parse(sltContextRaw) as SltContextData

      if (sltContext.finalized === '1') {
        this.logger.warn(`Attempt to increment attempts for already finalized SLT JTI ${sltJti}.`)
        throw new ApiException(HttpStatus.BAD_REQUEST, 'SltContextFinalized', 'Error.Auth.SltContext.AlreadyUsed')
      }

      sltContext.attempts += 1

      const ttl = await this.redisService.ttl(sltContextKey)
      if (ttl > 0) {
        await this.redisService.set(sltContextKey, JSON.stringify(sltContext), 'EX', ttl)
        this.logger.log(
          `SLT attempts incremented for JTI ${sltJti}. New attempts: ${sltContext.attempts}. Remaining TTL ${ttl}s.`
        )
      } else {
        this.logger.warn(
          `SLT context for JTI ${sltJti} expired before attempts could be incremented or had no TTL. Discarding increment.`
        )
      }

      this.auditLogService.recordAsync({
        userId: sltContext.userId,
        action: 'SLT_VERIFY_ATTEMPT_INCREMENTED',
        status: AuditLogStatus.FAILURE,
        ipAddress: sltContext.ipAddress,
        userAgent: sltContext.userAgent,
        details: {
          sltJti,
          purpose: sltContext.purpose,
          currentAttempts: sltContext.attempts,
          maxAttempts: MAX_SLT_ATTEMPTS
        } as Prisma.JsonObject
      })

      return sltContext.attempts
    } catch (error) {
      this.logger.error(
        `Error parsing or updating SLT context for JTI ${sltJti} during incrementSltAttempts: ${error.message}`,
        error.stack
      )
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
      this.logger.error(
        `SLT context for JTI ${sltContext.sltJti} is missing email, cannot verify OTP for purpose ${sltContext.purpose}.`
      )
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
        this.logger.log(
          `SLT JTI ${sltContext.sltJti} OTP verified for stage ${sltContext.purpose}. Metadata updated. Key: ${sltContextKey}`
        )
        this.auditLogService.recordAsync({
          userId: sltContext.userId,
          action: 'SLT_OTP_STAGE_VERIFIED',
          status: AuditLogStatus.SUCCESS,
          ipAddress: currentIpAddress,
          userAgent: currentUserAgent,
          details: {
            sltJti: sltContext.sltJti,
            purpose: sltContext.purpose,
            emailVerifiedAgainst: sltContext.email,
            metadataUpdated: sltContext.metadata
          } as Prisma.JsonObject
        })
      } else {
        this.logger.warn(
          `SLT JTI ${sltContext.sltJti} context expired before OTP stage verification metadata could be updated. This should ideally not happen if SLT is still valid.`
        )

        throw new ApiException(HttpStatus.CONFLICT, 'SltContextExpired', 'Error.Auth.Session.SltExpired')
      }
    } catch (error) {
      this.logger.warn(
        `OTP verification failed for SLT JTI ${sltContext.sltJti} (purpose: ${sltContext.purpose}). Error: ${error.message}`
      )
      const currentAttempts = await this.incrementSltAttempts(sltContext.sltJti)
      this.auditLogService.recordAsync({
        userId: sltContext.userId,
        action: 'SLT_OTP_STAGE_VERIFY_FAIL',
        status: AuditLogStatus.FAILURE,
        ipAddress: currentIpAddress,
        userAgent: currentUserAgent,
        errorMessage: error.message,
        details: {
          sltJti: sltContext.sltJti,
          purpose: sltContext.purpose,
          attempts: currentAttempts,
          maxAttempts: MAX_SLT_ATTEMPTS
        } as Prisma.JsonObject
      })

      if (currentAttempts >= MAX_SLT_ATTEMPTS) {
        this.logger.warn(
          `Max SLT attempts reached for JTI ${sltContext.sltJti} after failed OTP stage verification. Finalizing.`
        )
        await this.finalizeSlt(sltContext.sltJti)
        throw new MaxVerificationAttemptsExceededException()
      }

      if (error instanceof ApiException) throw error
      throw new InvalidOTPException()
    }
  }
}
