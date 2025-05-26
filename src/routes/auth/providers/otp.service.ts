import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import {
  TokenType,
  TokenTypeType,
  TypeOfVerificationCode,
  TypeOfVerificationCodeType
} from '../constants/auth.constants'
import envConfig from 'src/shared/config'
import { EmailService } from './email.service'
import { addMilliseconds } from 'date-fns'
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
  TooManyOTPAttemptsException
} from 'src/routes/auth/auth.error'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { JwtService } from '@nestjs/jwt'
import { AuditLogService, AuditLogStatus, AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'

interface OtpData {
  code: string
  attempts: number
  createdAt: number // Unix timestamp in milliseconds
  userId?: number
  deviceId?: number
  metadata?: Record<string, any>
}

export interface VerificationJwtPayload {
  jti: string
  sub: string // email
  type: TypeOfVerificationCodeType
  userId?: number
  deviceId?: number
  metadata?: Record<string, any>
  iat: number
  exp: number
}

// Define SLT Context and Payload
interface SltJwtPayload {
  jti: string
  sub?: number // userId, optional for anonymous flows like registration
  pur: TypeOfVerificationCodeType // purpose
  iat?: number // Optional: Issued at, jwtService will add this
  exp?: number // Optional: Expiration time, jwtService will add this
}

export interface SltContextData {
  userId: number // For reset password, this will be present. For register, might be initially undefined/null then updated, or not used until user creation.
  deviceId?: number // Made optional, esp. for registration flow before device is fully created
  ipAddress: string
  userAgent: string
  purpose: TypeOfVerificationCodeType
  sltJwtExp: number // SLT JWT expiry timestamp (seconds)
  sltJwtCreatedAt: number // SLT JWT creation timestamp (seconds)
  finalized: '0' | '1'
  metadata?: Record<string, any>
  // email might be useful here if OTP is sent to email based on this context
  email?: string
}

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
    // Consider renaming or creating a new prefix if this is purely for old verification JWTs
    return `${REDIS_KEY_PREFIX.VERIFICATION_JWT_BLACKLIST_JTI}${jti}`
  }

  private _getSltContextKey(jti: string): string {
    return `${REDIS_KEY_PREFIX.SLT_CONTEXT}${jti}`
  }

  async sendOTP(
    email: string,
    type: TypeOfVerificationCodeType,
    userIdForOtpData?: number
  ): Promise<{ message: string }> {
    const otpKey = this._getOtpKey(type, email)
    const code = generateOTP()
    const otpTTLSeconds = Math.floor(ms(envConfig.OTP_EXPIRES_IN) / 1000)

    const otpData: OtpData = {
      code,
      attempts: 0,
      createdAt: Date.now(),
      userId: userIdForOtpData // Store userId with OTP data if available and relevant
    }

    await this.redisService.set(otpKey, JSON.stringify(otpData), otpTTLSeconds)
    this.logger.debug(`OTP for ${type} for ${email} stored in Redis with TTL ${otpTTLSeconds}s. Key: ${otpKey}`)

    let title: string
    const lang = I18nContext.current()?.lang || 'en'

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
      case TypeOfVerificationCode.LOGIN_2FA:
        title = this.i18nService.translate('email.OTPSubject.Default', { lang })
        break
      case TypeOfVerificationCode.DISABLE_2FA:
        title = this.i18nService.translate('email.OTPSubject.Default', { lang })
        break
      case TypeOfVerificationCode.SETUP_2FA:
        title = this.i18nService.translate('email.OTPSubject.Default', { lang })
        break
      default:
        title = this.i18nService.translate('email.OTPSubject.Default', { lang })
    }

    try {
      await this.emailService.sendOTP({ email, code, title })
      this.auditLogService.recordAsync({
        userEmail: email,
        action: 'OTP_SENT',
        status: AuditLogStatus.SUCCESS,
        details: { type, emailSent: true } as Prisma.JsonObject
      })
      return { message: 'Auth.Otp.SentSuccessfully' }
    } catch (error) {
      this.logger.error(`Failed to send OTP to ${email} for type ${type}`, error)
      this.auditLogService.recordAsync({
        userEmail: email,
        action: 'OTP_SEND_FAILED',
        status: AuditLogStatus.FAILURE,
        errorMessage: error.message,
        details: { type } as Prisma.JsonObject
      })
      throw FailedToSendOTPException
    }
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
    const { otpKey, otpData } = await this._verifyOtpCore(
      payload.email,
      payload.code,
      payload.type,
      payload.ip,
      payload.userAgent
    )
    // If OTP is valid, otpData is returned and otpKey is deleted by _verifyOtpCore

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
      details: { ...otpData, verificationJwtJti: jwtJti } as Prisma.JsonObject
    })

    return verificationJwt
  }

  // New method to only verify OTP
  async verifyOtpOnly(
    email: string,
    code: string,
    type: TypeOfVerificationCodeType,
    userId?: number, // For audit logging
    ip?: string,
    userAgent?: string
  ): Promise<boolean> {
    await this._verifyOtpCore(email, code, type, ip, userAgent, userId)
    return true // If _verifyOtpCore doesn't throw, OTP is valid
  }

  // Internal core OTP verification logic, extracted from verifyOTPAndCreateToken
  private async _verifyOtpCore(
    email: string,
    code: string,
    type: TypeOfVerificationCodeType,
    ip?: string,
    userAgent?: string,
    userIdForAudit?: number // Optional userId for more specific auditing
  ): Promise<{ otpKey: string; otpData: OtpData }> {
    const otpKey = this._getOtpKey(type, email)
    const otpDataString = await this.redisService.get(otpKey)

    const auditDetailsBase: Record<string, any> = {
      email: email,
      type: type,
      otpProvided: code,
      ip: ip,
      userAgent: userAgent,
      userId: userIdForAudit // Include userId in audit if provided
    }

    if (!otpDataString) {
      this.logger.warn(`OTP verification failed: No OTP data found for key ${otpKey}`)
      this.auditLogService.recordAsync({
        userEmail: email,
        userId: userIdForAudit,
        action: 'OTP_VERIFY_FAIL',
        status: AuditLogStatus.FAILURE,
        errorMessage: 'OTP_EXPIRED_OR_NOT_FOUND',
        details: auditDetailsBase as Prisma.JsonObject
      })
      throw OTPExpiredException
    }

    const otpData: OtpData = JSON.parse(otpDataString)

    if (otpData.attempts >= this.MAX_OTP_ATTEMPTS) {
      this.logger.warn(`OTP verification failed: Max attempts reached for key ${otpKey}`)
      await this.redisService.del(otpKey) // Delete on max attempts
      this.auditLogService.recordAsync({
        userEmail: email,
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
        await this.redisService.set(otpKey, JSON.stringify(otpData), ttl)
      }
      this.logger.warn(
        `OTP verification failed: Invalid code for key ${otpKey}. Attempt ${otpData.attempts}/${this.MAX_OTP_ATTEMPTS}`
      )
      this.auditLogService.recordAsync({
        userEmail: email,
        userId: userIdForAudit,
        action: 'OTP_VERIFY_FAIL',
        status: AuditLogStatus.FAILURE,
        errorMessage: 'INVALID_OTP_CODE',
        details: { ...auditDetailsBase, attempts: otpData.attempts } as Prisma.JsonObject
      })
      throw InvalidOTPException
    }

    await this.redisService.del(otpKey) // OTP verified, delete it.
    this.logger.debug(`OTP for key ${otpKey} verified and deleted from Redis.`)

    // Audit success for OTP verification part
    this.auditLogService.recordAsync({
      userEmail: email,
      userId: userIdForAudit,
      action: 'OTP_VERIFY_ONLY_SUCCESS',
      status: AuditLogStatus.SUCCESS,
      details: { ...auditDetailsBase, type } as Prisma.JsonObject
    })
    return { otpKey, otpData }
  }

  async initiateOtpWithSltCookie(payload: {
    email: string // To send OTP
    userId: number // Keep as number for now, assuming it's available for flows using this
    deviceId?: number // Made optional
    ipAddress: string
    userAgent: string
    purpose: TypeOfVerificationCodeType
    metadata?: Record<string, any>
  }): Promise<string> {
    const { email, userId, deviceId, ipAddress, userAgent, purpose, metadata } = payload

    // 1. Send OTP (can pass userId to sendOTP if it needs to store it with OtpData)
    await this.sendOTP(email, purpose, userId) // Pass userId to link OTP to user in OtpData

    // 2. Create SLT JWT
    const sltJti = uuidv4()
    const sltExpiresInSeconds = Math.floor(ms(envConfig.SLT_JWT_EXPIRES_IN) / 1000)

    // Payload for JWT signing should only contain claims we set. 'iat' and 'exp' are handled by jwtService.sign
    const sltJwtSigningPayload: Pick<SltJwtPayload, 'jti' | 'sub' | 'pur'> = {
      jti: sltJti,
      sub: userId,
      pur: purpose
    }

    const sltJwt = this.jwtService.sign(sltJwtSigningPayload, {
      secret: envConfig.SLT_JWT_SECRET,
      expiresIn: envConfig.SLT_JWT_EXPIRES_IN
    })

    // 3. Store SLT Context in Redis
    const sltContextKey = this._getSltContextKey(sltJti)
    const nowForContext = Math.floor(Date.now() / 1000) // Get current time for context
    const sltContextData: SltContextData = {
      userId: payload.userId,
      deviceId: payload.deviceId, // Will be undefined if not provided
      ipAddress: payload.ipAddress,
      userAgent: payload.userAgent,
      purpose,
      sltJwtExp: nowForContext + sltExpiresInSeconds, // Calculate exp for context based on current time and expiresIn
      sltJwtCreatedAt: nowForContext, // Record creation time for context
      finalized: '0',
      metadata,
      email
    }

    await this.redisService.set(sltContextKey, JSON.stringify(sltContextData), sltExpiresInSeconds)
    this.logger.debug(
      `SLT context for JTI ${sltJti} (purpose ${purpose}) stored in Redis with TTL ${sltExpiresInSeconds}s. Key: ${sltContextKey}`
    )
    this.auditLogService.recordAsync({
      userId,
      userEmail: email,
      action: 'SLT_CONTEXT_CREATED',
      status: AuditLogStatus.SUCCESS,
      ipAddress,
      userAgent,
      details: {
        sltJti,
        purpose,
        deviceId,
        sltContextKey,
        sltExpiresInSeconds
      } as Prisma.JsonObject
    })

    return sltJwt
  }

  async validateSltFromCookieAndGetContext(
    sltCookieValue: string,
    currentIpAddress: string,
    currentUserAgent: string,
    expectedPurpose?: TypeOfVerificationCodeType // Made optional
  ): Promise<SltContextData & { sltJti: string }> {
    // Return JTI as well for convenience
    let sltPayloadFromVerify: SltJwtPayload // This will include iat and exp from jwtService.verify
    try {
      sltPayloadFromVerify = this.jwtService.verify<SltJwtPayload>(sltCookieValue, {
        secret: envConfig.SLT_JWT_SECRET
      })
    } catch (error) {
      this.logger.warn(`SLT JWT verification failed: ${error.message}. Token: ${sltCookieValue.substring(0, 20)}...`)
      // Log audit for failed SLT validation attempt
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
      ]) // Generic error
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

    // Verify JWT expiry against Redis stored expiry to ensure consistency, and also current time
    const nowSeconds = Math.floor(Date.now() / 1000)
    if (sltExpFromJwt !== sltContext.sltJwtExp || nowSeconds >= sltContext.sltJwtExp) {
      this.logger.warn(
        `SLT JWT/Context expiry mismatch or SLT expired for JTI ${sltJti}. JWT exp: ${sltExpFromJwt}, Context exp: ${sltContext.sltJwtExp}, Now: ${nowSeconds}`
      )
      // Clean up if expired
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

    // Optional: Stricter IP and User Agent check (can be made configurable)
    // if (envConfig.SLT_STRICT_IP_UA_CHECK) { // Example: make it configurable
    //   if (sltContext.ipAddress !== currentIpAddress || sltContext.userAgent !== currentUserAgent) {
    //     this.logger.warn(
    //       `SLT IP/UserAgent mismatch for JTI ${sltJti}. Context: [${sltContext.ipAddress}, ${sltContext.userAgent}], Current: [${currentIpAddress}, ${currentUserAgent}]`
    //     );
    //     // Decide if this is a hard fail or just a warning/audit
    //     throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Device.Mismatch');
    //   }
    // }

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
    const result = await this.redisService.del(sltContextKey) // Delete the context key
    if (result > 0) {
      this.logger.debug(`SLT context for JTI ${sltJti} finalized and deleted from Redis.`)
      this.auditLogService.recordAsync({
        action: 'SLT_CONTEXT_FINALIZED',
        status: AuditLogStatus.SUCCESS,
        details: { sltJti, sltContextKey } as Prisma.JsonObject
      })
    } else {
      this.logger.warn(
        `Attempted to finalize SLT context for JTI ${sltJti}, but key was not found or already deleted. Key: ${sltContextKey}`
      )
      // Audit this too, as it might indicate a double finalization attempt or an issue.
      this.auditLogService.recordAsync({
        action: 'SLT_FINALIZE_WARN_NOT_FOUND',
        status: AuditLogStatus.FAILURE, // Or WARNING if such status exists
        errorMessage: 'SLT_CONTEXT_KEY_NOT_FOUND_ON_FINALIZE',
        details: { sltJti, sltContextKey } as Prisma.JsonObject
      })
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
    tx?: PrismaTransactionClient // tx is not used here, Redis operations are separate
  }): Promise<string> {
    this.logger.warn(
      `[OtpService] createLoginSessionToken is deprecated and will be removed. Use SLT mechanism. Called for: ${payload.email}, type: ${payload.type}`
    )
    const { email, type, userId, deviceId, metadata } = payload
    const jti = uuidv4()
    const now = Math.floor(Date.now() / 1000)
    const expiresInSeconds = 5 * 60 // 5 minutes for login session token
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
    // Store payload in Redis for potential detailed validation/revocation if needed later, though not strictly necessary for this type of token
    // await this.redisService.setJson(this._getVerificationJwtPayloadKey(jti), tokenPayload, expiresInSeconds)

    // jwtService.sign is synchronous by default
    const signedToken = this.jwtService.sign(tokenPayload, { secret: envConfig.VERIFICATION_JWT_SECRET })
    return Promise.resolve(signedToken) // Wrap in Promise.resolve to match return type
  }

  async blacklistVerificationToken(
    jti: string,
    currentTimestamp: number,
    expiresAtTimestamp: number,
    tx?: PrismaTransactionClient
  ): Promise<void> {
    // tx is not used here as Redis operations are typically outside DB transactions
    this.logger.warn(
      `[OtpService] blacklistVerificationToken is part of an older OTP flow. Called for JTI: ${jti}. Consider SLT finalization for new flows.`
    )
    const blacklistKey = this._getVerificationJwtBlacklistKey(jti)
    const ttl = expiresAtTimestamp - currentTimestamp
    if (ttl > 0) {
      await this.redisService.set(blacklistKey, 'blacklisted', ttl)
      this.logger.debug(`Blacklisted verification token JTI: ${jti} for ${ttl} seconds.`)
    }
  }

  async validateVerificationToken(
    token: string,
    expectedType: TypeOfVerificationCodeType,
    expectedEmail?: string,
    expectedDeviceId?: number
    // tx is not used here
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
      throw InvalidOTPTokenException // Re-throw as specific exception
    }

    const blacklistKey = this._getVerificationJwtBlacklistKey(payload.jti)
    if (await this.redisService.exists(blacklistKey)) {
      this.logger.warn(`Attempt to use blacklisted verification token JTI: ${payload.jti}`)
      throw OTPTokenExpiredException // Or a more specific "already used" exception
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

    // Optional: Validate against stored payload in Redis if it exists (though createLoginSessionToken does not store it)
    // const storedPayloadString = await this.redisService.get(this._getVerificationJwtPayloadKey(payload.jti));
    // if (storedPayloadString) { ... compare ... }

    return payload
  }

  async sendOtpAndInitiateSltForAnonymous(payload: {
    email: string // To send OTP
    ipAddress: string
    userAgent: string
    purpose: TypeOfVerificationCode.REGISTER | TypeOfVerificationCode.RESET_PASSWORD // Specify limited purposes
    metadata?: Record<string, any>
  }): Promise<string> {
    const { email, ipAddress, userAgent, purpose, metadata } = payload

    const sltExpiresInSeconds = envConfig.SLT_EXPIRY_SECONDS
    const sltJti = uuidv4()

    const sltJwtPayloadToSign: Pick<SltJwtPayload, 'jti' | 'pur'> = {
      jti: sltJti,
      pur: purpose
    }

    const sltToken = this.jwtService.sign(sltJwtPayloadToSign, {
      secret: envConfig.SLT_JWT_SECRET,
      expiresIn: envConfig.SLT_JWT_EXPIRES_IN
    })

    // Send OTP email (this part remains largely the same)
    try {
      await this.sendOTP(email, purpose, undefined /* userIdForOtpData */) // sendOTP now handles optional userId
    } catch (error) {
      this.logger.error(`Failed to send OTP for ${purpose} to ${email}: ${error.message}`)
      // Even if OTP sending fails, we might have created an SLT. Decide on rollback or let it expire.
      // For now, we throw, and the caller handles cleanup or relies on SLT expiry.
      throw error // Re-throw to be handled by the caller
    }

    const nowForContext = Math.floor(Date.now() / 1000) // Get current time for context
    const sltContextData: SltContextData = {
      // userId and deviceId are not set for anonymous flow initially
      userId: null as any, // Explicitly null, will be updated later if needed or not used
      deviceId: undefined,
      email: email, // Store email in context for anonymous flows
      ipAddress: ipAddress,
      userAgent: userAgent,
      purpose: purpose,
      sltJwtExp: nowForContext + sltExpiresInSeconds,
      sltJwtCreatedAt: nowForContext,
      finalized: '0',
      metadata: { ...(metadata || {}), otpVerified: '0' } // Initialize otpVerified in metadata
    }

    const sltContextKey = this._getSltContextKey(sltJti)
    await this.redisService.setJson(sltContextKey, sltContextData, sltExpiresInSeconds)

    this.logger.debug(
      `Anonymous SLT context for JTI ${sltJti} (purpose ${purpose}, email ${email}) stored in Redis with TTL ${sltExpiresInSeconds}s. Key: ${sltContextKey}`
    )

    this.auditLogService.recordAsync({
      action: 'ANONYMOUS_SLT_INITIATED_WITH_OTP',
      status: AuditLogStatus.SUCCESS,
      userEmail: email,
      ipAddress: ipAddress,
      userAgent: userAgent,
      details: {
        sltJti,
        purpose,
        email,
        metadata,
        sltExpiresInSeconds
      } as Prisma.JsonObject
    })

    return sltToken
  }

  async markSltOtpAsVerified(sltJti: string): Promise<boolean> {
    const sltContextKey = this._getSltContextKey(sltJti)
    const sltContextString = await this.redisService.get(sltContextKey)

    if (!sltContextString) {
      this.logger.warn(`Cannot mark OTP as verified: SLT context not found for JTI ${sltJti}. Key: ${sltContextKey}`)
      // Potentially throw an error or return false if context must exist
      return false
    }

    const sltContext: SltContextData = JSON.parse(sltContextString)

    if (sltContext.finalized === '1') {
      this.logger.warn(`Cannot mark OTP as verified for JTI ${sltJti}: SLT context is already finalized.`)
      return false // Or throw error
    }

    // Update metadata
    const updatedMetadata = {
      ...(sltContext.metadata || {}),
      otpVerified: '1'
    }
    const updatedContext: SltContextData = {
      ...sltContext,
      metadata: updatedMetadata
    }

    const ttl = await this.redisService.ttl(sltContextKey)
    if (ttl > 0) {
      await this.redisService.setJson(sltContextKey, updatedContext, ttl)
      this.logger.debug(`SLT context JTI ${sltJti} marked with otpVerified='1'. Key: ${sltContextKey}`)
      this.auditLogService.recordAsync({
        action: 'SLT_OTP_MARKED_VERIFIED',
        status: AuditLogStatus.SUCCESS,
        userEmail: sltContext.email,
        userId: sltContext.userId !== null ? sltContext.userId : undefined, // Handle potential null userId
        ipAddress: sltContext.ipAddress,
        userAgent: sltContext.userAgent,
        details: {
          sltJti,
          purpose: sltContext.purpose
        } as Prisma.JsonObject
      })
      return true
    } else {
      this.logger.warn(
        `SLT context for JTI ${sltJti} has expired or has no TTL. Cannot mark OTP as verified. Key: ${sltContextKey}`
      )
      return false
    }
  }
}
