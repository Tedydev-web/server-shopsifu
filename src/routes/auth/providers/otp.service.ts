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
  InvalidOTPTokenException,
  OTPTokenExpiredException,
  DeviceMismatchException,
  TooManyOTPAttemptsException,
  TooManyRequestsException
} from 'src/routes/auth/auth.error'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { JwtService } from '@nestjs/jwt'
import { AuditLogService, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'

interface OtpData {
  code: string
  attempts: number
  createdAt: number // Unix timestamp in milliseconds
  userId?: number // ID của user mà OTP này gắn liền (cho VERIFY_NEW_EMAIL thì đây là user ID)
  deviceId?: number
  metadata?: Record<string, any>
}

export interface VerificationJwtPayload {
  jti: string
  sub: string // email (có thể là email chính hoặc pendingEmail tùy context)
  type: TypeOfVerificationCodeType
  userId?: number // Luôn là ID của user
  deviceId?: number
  metadata?: Record<string, any>
  iat: number
  exp: number
}

interface SltJwtPayload {
  jti: string
  sub: number // userId
  pur: TypeOfVerificationCodeType // purpose
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
  email?: string // Email đích cho OTP (ví dụ: pendingEmail)
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

  private _getVerificationJwtPayloadKey(jti: string): string {
    return `${REDIS_KEY_PREFIX.VERIFICATION_JWT_PAYLOAD}${jti}`
  }

  private _getVerificationJwtBlacklistKey(jti: string): string {
    return `${REDIS_KEY_PREFIX.VERIFICATION_JWT_BLACKLIST_JTI}${jti}`
  }

  private _getSltContextKey(jti: string): string {
    return `${REDIS_KEY_PREFIX.SLT_CONTEXT}${jti}`
  }

  private _getOtpLastSentKey(identifierForCooldown: string, purpose: TypeOfVerificationCodeType): string {
    return `${REDIS_KEY_PREFIX.OTP_LAST_SENT}${identifierForCooldown}:${purpose}`
  }

  async sendOTP(
    targetEmail: string, // Email đích để gửi OTP
    type: TypeOfVerificationCodeType,
    userIdForCooldownAndOtpData?: number // User ID thực hiện hành động (để rate limit và lưu trong OtpData)
  ): Promise<{ message: string }> {
    const lang = I18nContext.current()?.lang || 'en'

    if (userIdForCooldownAndOtpData) {
      const cooldownIdentifier = userIdForCooldownAndOtpData.toString() // Sửa lỗi linter: chuyển sang string
      const cooldownKey = this._getOtpLastSentKey(cooldownIdentifier, type)
      const lastSentTimestampStr = await this.redisService.get(cooldownKey)
      if (lastSentTimestampStr) {
        const lastSentTimestamp = parseInt(lastSentTimestampStr, 10)
        if (Date.now() - lastSentTimestamp < OTP_SEND_COOLDOWN_SECONDS * 1000) {
          this.logger.warn(`OTP send cooldown active for identifier ${cooldownIdentifier}, type ${type}.`)
          throw TooManyRequestsException(
            await this.i18nService.translate('error.Error.Auth.Otp.CooldownActive', {
              lang,
              args: { seconds: OTP_SEND_COOLDOWN_SECONDS }
            })
          )
        }
      }
    }

    const otpKey = this._getOtpKey(type, targetEmail) // OTP key dựa trên email đích và type
    const code = generateOTP()
    const otpTTLSeconds = Math.floor(ms(envConfig.OTP_EXPIRES_IN) / 1000)

    const otpData: OtpData = {
      code,
      attempts: 0,
      createdAt: Date.now(),
      userId: userIdForCooldownAndOtpData // userId của người thực hiện hành động
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
        const cooldownIdentifier = userIdForCooldownAndOtpData.toString() // Sửa lỗi linter: chuyển sang string
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
    emailToVerifyAgainst: string, // Email dùng để tạo otpKey (VD: pendingEmail)
    code: string,
    type: TypeOfVerificationCodeType,
    userIdForAudit?: number, // User ID thực hiện hành động
    ip?: string,
    userAgent?: string
  ): Promise<boolean> {
    await this._verifyOtpCore(emailToVerifyAgainst, code, type, ip, userAgent, userIdForAudit)
    return true
  }

  private async _verifyOtpCore(
    identifierForOtpKey: string, // Email hoặc ID dùng trong _getOtpKey
    code: string,
    type: TypeOfVerificationCodeType,
    ip?: string,
    userAgent?: string,
    userIdForAudit?: number // User ID thực hiện hành động
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
      throw OTPExpiredException
    }

    const otpData: OtpData = JSON.parse(otpDataString)

    // Đối với VERIFY_NEW_EMAIL, kiểm tra xem userId trong OtpData có khớp với userIdForAudit không
    if (type === TypeOfVerificationCode.VERIFY_NEW_EMAIL && otpData.userId !== userIdForAudit) {
      this.logger.warn(
        `OTP verification failed for ${identifierForOtpKey} (type ${type}): OTP data user ID (${otpData.userId}) does not match audit user ID (${userIdForAudit}). Key: ${otpKey}`
      )
      otpData.attempts += 1 // Tăng số lần thử cho key OTP cụ thể này
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
      throw InvalidOTPException // Hoặc lỗi cụ thể hơn
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
      throw TooManyOTPAttemptsException
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
      throw InvalidOTPException
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
    email: string // Email đích để gửi OTP (VD: pendingEmail cho VERIFY_NEW_EMAIL)
    userId: number // User ID thực hiện hành động
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
        throw TooManyRequestsException(
          await this.i18nService.translate('error.Error.Auth.Otp.CooldownActive', {
            lang,
            args: { seconds: OTP_SEND_COOLDOWN_SECONDS }
          })
        )
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
      email // Lưu email đích (pendingEmail) trong context
    }

    const sltContextKey = this._getSltContextKey(sltJti)
    await this.redisService.set(sltContextKey, JSON.stringify(sltContextDataToStore), 'EX', sltExpiresInSeconds)
    this.logger.debug(`SLT context for JTI ${sltJti} stored in Redis. Key: ${sltContextKey}`)

    if (
      purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP ||
      purpose === TypeOfVerificationCode.REVERIFY_SESSION_OTP ||
      purpose === TypeOfVerificationCode.VERIFY_NEW_EMAIL // Thêm VERIFY_NEW_EMAIL
    ) {
      // "email" trong payload là email đích (targetEmail) để gửi OTP.
      // "userId" trong payload là userId thực tế của người dùng để rate limiting và lưu trong OtpData.
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
        targetEmail: email, // Log email đích
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
    email: string // Identifier for OTP key
    code: string
    type: TypeOfVerificationCodeType
    userId?: number // The actual user ID
    deviceId?: number
    metadata?: Record<string, any>
    ip?: string
    userAgent?: string
  }): Promise<string> {
    const { otpData } = await this._verifyOtpCore(
      payload.email,
      payload.code,
      payload.type,
      payload.ip,
      payload.userAgent,
      payload.userId
    )

    const jwtJti = uuidv4()
    const nowSeconds = Math.floor(Date.now() / 1000)
    const expiresInSeconds = Math.floor(ms(envConfig.VERIFICATION_JWT_EXPIRES_IN) / 1000)

    const verificationJwtPayload: VerificationJwtPayload = {
      jti: jwtJti,
      sub: payload.email,
      type: payload.type,
      userId: payload.userId,
      deviceId: payload.deviceId,
      metadata: payload.metadata,
      iat: nowSeconds,
      exp: nowSeconds + expiresInSeconds
    }

    const verificationJwt = this.jwtService.sign(verificationJwtPayload, {
      secret: envConfig.VERIFICATION_JWT_SECRET,
      expiresIn: envConfig.VERIFICATION_JWT_EXPIRES_IN
    })

    await this.redisService.set(
      this._getVerificationJwtPayloadKey(jwtJti),
      JSON.stringify(verificationJwtPayload),
      'EX',
      expiresInSeconds
    )
    this.logger.debug(
      `Verification JWT payload for JTI ${jwtJti} stored in Redis. Key: ${this._getVerificationJwtPayloadKey(jwtJti)}`
    )

    this.auditLogService.recordAsync({
      userEmail: payload.email,
      action: 'OTP_VERIFY_SUCCESS_JWT_CREATED',
      userId: payload.userId,
      status: AuditLogStatus.SUCCESS,
      details: { ...otpData, verificationJwtJti: jwtJti, forUserId: payload.userId } as Prisma.JsonObject
    })

    return verificationJwt
  }

  async validateSltFromCookieAndGetContext(
    sltCookieValue: string,
    currentIpAddress: string,
    currentUserAgent: string,
    expectedPurpose?: TypeOfVerificationCodeType
  ): Promise<SltContextData & { sltJti: string }> {
    let sltPayloadFromVerify: SltJwtPayload
    try {
      sltPayloadFromVerify = this.jwtService.verify<SltJwtPayload>(sltCookieValue, {
        secret: envConfig.SLT_JWT_SECRET
      })
    } catch (error) {
      this.logger.warn(`SLT JWT verification failed: ${error.message}. Token: ${sltCookieValue.substring(0, 20)}...`)
      this.auditLogService.recordAsync({
        action: 'SLT_VALIDATION_FAIL',
        status: AuditLogStatus.FAILURE,
        ipAddress: currentIpAddress,
        userAgent: currentUserAgent,
        errorMessage: 'INVALID_SLT_JWT_SIGNATURE_OR_EXPIRED',
        details: {
          error: error.message,
          expectedPurposeProvided: !!expectedPurpose,
          expectedPurposeValue: expectedPurpose
        } as Prisma.JsonObject
      })
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'AuthenticationError', 'Error.Auth.Session.InvalidLogin', [
        { code: 'Error.Auth.Session.InvalidLogin', path: 'slt_token' }
      ])
    }

    const { jti: sltJti, pur: sltPurposeFromJwt, sub: sltUserId, exp: sltExpFromJwt } = sltPayloadFromVerify

    const auditDetails: Record<string, any> = {
      sltJti,
      sltPurposeFromJwt,
      sltUserId,
      expectedPurposeProvided: !!expectedPurpose,
      expectedPurposeValue: expectedPurpose,
      currentIpAddress,
      currentUserAgent
    }

    if (expectedPurpose && sltPurposeFromJwt !== expectedPurpose) {
      this.logger.warn(`SLT purpose mismatch for JTI ${sltJti}. Expected ${expectedPurpose}, got ${sltPurposeFromJwt}.`)
      this.auditLogService.recordAsync({
        userId: sltUserId,
        action: 'SLT_VALIDATION_FAIL',
        status: AuditLogStatus.FAILURE,
        ipAddress: currentIpAddress,
        userAgent: currentUserAgent,
        errorMessage: 'SLT_PURPOSE_MISMATCH',
        details: auditDetails as Prisma.JsonObject
      })
      throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Session.InvalidLogin', [
        { code: 'Error.Auth.Session.InvalidLogin', path: 'slt_token' }
      ])
    }

    const sltContextKey = this._getSltContextKey(sltJti)
    const sltContextString = await this.redisService.get(sltContextKey)

    if (!sltContextString) {
      this.logger.warn(`SLT context not found in Redis for JTI ${sltJti}. Key: ${sltContextKey}.`)
      this.auditLogService.recordAsync({
        userId: sltUserId,
        action: 'SLT_VALIDATION_FAIL',
        status: AuditLogStatus.FAILURE,
        ipAddress: currentIpAddress,
        userAgent: currentUserAgent,
        errorMessage: 'SLT_CONTEXT_NOT_FOUND_OR_EXPIRED_IN_REDIS',
        details: auditDetails as Prisma.JsonObject
      })
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'AuthenticationError', 'Error.Auth.Session.InvalidLogin', [
        { code: 'Error.Auth.Session.InvalidLogin', path: 'slt_token' }
      ])
    }

    const sltContext: SltContextData = JSON.parse(sltContextString)

    if (sltContext.finalized === '1') {
      this.logger.warn(`Attempt to use an already finalized SLT context for JTI ${sltJti}.`)
      this.auditLogService.recordAsync({
        userId: sltUserId,
        action: 'SLT_VALIDATION_FAIL',
        status: AuditLogStatus.FAILURE,
        ipAddress: currentIpAddress,
        userAgent: currentUserAgent,
        errorMessage: 'SLT_CONTEXT_ALREADY_FINALIZED',
        details: auditDetails as Prisma.JsonObject
      })
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'AuthenticationError', 'Error.Auth.Session.InvalidLogin', [
        { code: 'Error.Auth.Session.InvalidLogin', path: 'slt_token' }
      ])
    }

    const nowSeconds = Math.floor(Date.now() / 1000)
    if (sltExpFromJwt !== sltContext.sltJwtExp || nowSeconds >= sltContext.sltJwtExp) {
      this.logger.warn(
        `SLT JWT/Context expiry mismatch or SLT expired for JTI ${sltJti}. JWT exp: ${sltExpFromJwt}, Context exp: ${sltContext.sltJwtExp}, Now: ${nowSeconds}`
      )
      if (nowSeconds >= sltContext.sltJwtExp) await this.redisService.del(sltContextKey)
      this.auditLogService.recordAsync({
        userId: sltUserId,
        action: 'SLT_VALIDATION_FAIL',
        status: AuditLogStatus.FAILURE,
        ipAddress: currentIpAddress,
        userAgent: currentUserAgent,
        errorMessage: 'SLT_EXPIRED_OR_EXPIRY_MISMATCH',
        details: {
          ...auditDetails,
          jwtExp: sltExpFromJwt,
          contextExp: sltContext.sltJwtExp,
          actualPurposeInContext: sltContext.purpose
        } as Prisma.JsonObject
      })
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'AuthenticationError', 'Error.Auth.Session.InvalidLogin', [
        { code: 'Error.Auth.Session.InvalidLogin', path: 'slt_token' }
      ])
    }

    if (currentIpAddress !== sltContext.ipAddress) {
      this.logger.warn(
        `SLT JTI ${sltJti}: IP address mismatch. Context IP: ${sltContext.ipAddress}, Current IP: ${currentIpAddress}.`
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
          sltJti,
          expectedIp: sltContext.ipAddress,
          actualIp: currentIpAddress,
          expectedUserAgent: sltContext.userAgent,
          actualUserAgent: currentUserAgent
        } as Prisma.JsonObject
      })
      await this.finalizeSlt(sltJti)
      throw DeviceMismatchException
    }

    this.auditLogService.recordAsync({
      userId: sltUserId,
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
    return { ...sltContext, sltJti }
  }

  async finalizeSlt(sltJti: string): Promise<void> {
    const sltContextKey = this._getSltContextKey(sltJti)
    const sltContextRaw = await this.redisService.get(sltContextKey)

    if (!sltContextRaw) {
      this.logger.warn(`SLT context for JTI ${sltJti} not found in Redis during finalize. Key: ${sltContextKey}`)
      return
    }

    try {
      const sltContext = JSON.parse(sltContextRaw) as SltContextData
      if (sltContext.finalized === '1') {
        this.logger.log(`SLT context for JTI ${sltJti} is already finalized. Skipping re-finalization.`)
        return
      }

      sltContext.finalized = '1'
      const ttl = await this.redisService.ttl(sltContextKey)
      if (ttl > 0) {
        await this.redisService.set(sltContextKey, JSON.stringify(sltContext), 'EX', ttl)
        this.logger.log(`SLT context for JTI ${sltJti} marked as finalized in Redis with remaining TTL ${ttl}s.`)
      } else {
        await this.redisService.set(sltContextKey, JSON.stringify(sltContext), 'EX', 60)
        this.logger.log(
          `SLT context for JTI ${sltJti} marked as finalized in Redis. Original TTL was <=0, set with 60s TTL.`
        )
      }

      this.auditLogService.recordAsync({
        userId: sltContext.userId,
        action: 'SLT_FINALIZED',
        status: AuditLogStatus.SUCCESS,
        ipAddress: sltContext.ipAddress,
        userAgent: sltContext.userAgent,
        details: { sltJti, purpose: sltContext.purpose } as Prisma.JsonObject
      })
    } catch (error) {
      this.logger.error(`Error parsing SLT context for JTI ${sltJti} during finalize: ${error.message}`, error.stack)
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
      throw new ApiException(HttpStatus.BAD_REQUEST, 'SltContextInvalid', 'Error.Auth.OtpToken.Invalid')
    }

    try {
      const sltContext = JSON.parse(sltContextRaw) as SltContextData

      if (sltContext.finalized === '1') {
        this.logger.warn(`Attempt to increment attempts for already finalized SLT JTI ${sltJti}.`)
        throw new ApiException(HttpStatus.BAD_REQUEST, 'SltContextFinalized', 'Error.Auth.OtpToken.AlreadyUsed')
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
        throw new ApiException(HttpStatus.BAD_REQUEST, 'SltContextExpired', 'Error.Auth.OtpToken.Expired')
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

  /**
   * @deprecated This method creates a short-lived JWT primarily for multi-step auth flows like 2FA.
   * It's being replaced by the State-Linking Token (SLT) mechanism.
   * Use initiateOtpWithSltCookie for new flows requiring an OTP step followed by verification.
   */
  createLoginSessionToken(payload: {
    email: string
    type: TypeOfVerificationCodeType
    userId: number
    deviceId: number
    metadata?: Record<string, any>
    tx?: PrismaTransactionClient
  }): Promise<string> {
    this.logger.warn(
      `[OtpService] createLoginSessionToken is deprecated and will be removed. Use SLT mechanism. Called for: ${payload.email}, type: ${payload.type}`
    )
    const { email, type, userId, deviceId, metadata } = payload
    const jti = uuidv4()
    const now = Math.floor(Date.now() / 1000)
    const expiresInSeconds = 5 * 60 // 5 minutes
    const expiresAt = now + expiresInSeconds

    const tokenPayload: VerificationJwtPayload = {
      jti,
      sub: email,
      type,
      userId,
      deviceId,
      metadata,
      iat: now,
      exp: expiresAt
    }
    const signedToken = this.jwtService.sign(tokenPayload, { secret: envConfig.VERIFICATION_JWT_SECRET })
    return Promise.resolve(signedToken)
  }

  async blacklistVerificationToken(
    jti: string,
    currentTimestamp: number,
    expiresAtTimestamp: number,
    tx?: PrismaTransactionClient
  ): Promise<void> {
    this.logger.warn(
      `[OtpService] blacklistVerificationToken is part of an older OTP flow. Called for JTI: ${jti}. Consider SLT finalization for new flows.`
    )
    const blacklistKey = this._getVerificationJwtBlacklistKey(jti)
    const ttl = expiresAtTimestamp - currentTimestamp
    if (ttl > 0) {
      await this.redisService.set(blacklistKey, 'blacklisted', 'EX', ttl)
      this.logger.debug(`Blacklisted verification token JTI: ${jti} for ${ttl} seconds.`)
    }
  }

  async validateVerificationToken(
    token: string,
    expectedType: TypeOfVerificationCodeType,
    expectedEmail?: string,
    expectedDeviceId?: number
  ): Promise<VerificationJwtPayload> {
    this.logger.warn(
      `[OtpService] validateVerificationToken is part of an older OTP flow. Called for token (type ${expectedType}). Consider SLT validation for new flows.`
    )
    let payload: VerificationJwtPayload
    try {
      payload = this.jwtService.verify<VerificationJwtPayload>(token, { secret: envConfig.VERIFICATION_JWT_SECRET })
    } catch (error) {
      this.logger.warn(`
        Failed to verify old verification token: ${error.message}.
        Token: ${token.substring(0, 20)}...
        Expected Type: ${expectedType}
      `)
      throw InvalidOTPTokenException
    }

    const blacklistKey = this._getVerificationJwtBlacklistKey(payload.jti)
    if (await this.redisService.exists(blacklistKey)) {
      this.logger.warn(`Attempt to use blacklisted verification token JTI: ${payload.jti}`)
      throw OTPTokenExpiredException
    }

    const now = Math.floor(Date.now() / 1000)
    if (payload.exp < now) {
      this.logger.warn(`Old verification token expired: JTI ${payload.jti}, EXP ${payload.exp}, NOW ${now}`)
      throw OTPTokenExpiredException
    }

    if (payload.type !== expectedType) {
      this.logger.warn(
        `Old verification token type mismatch: JTI ${payload.jti}, Expected ${expectedType}, Got ${payload.type}`
      )
      throw InvalidOTPTokenException
    }

    if (expectedEmail && payload.sub !== expectedEmail) {
      this.logger.warn(
        `Old verification token email mismatch: JTI ${payload.jti}, Expected ${expectedEmail}, Got ${payload.sub}`
      )
      throw InvalidOTPTokenException
    }

    if (expectedDeviceId && payload.deviceId !== expectedDeviceId) {
      this.logger.warn(
        `Old verification token deviceId mismatch: JTI ${payload.jti}, Expected ${expectedDeviceId}, Got ${payload.deviceId}`
      )
      throw DeviceMismatchException
    }
    return payload
  }
}
