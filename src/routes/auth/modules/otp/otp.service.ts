import { Injectable, Logger, Inject } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import {
  TypeOfVerificationCodeType,
  OTP_LENGTH,
  SLT_EXPIRY_SECONDS,
  SLT_MAX_ATTEMPTS,
  OTP_COOLDOWN_SECONDS,
  TwoFactorMethodType
} from 'src/shared/constants/auth.constants'
import { OtpData, SltContextData, SltJwtPayload } from 'src/routes/auth/auth.types'
import { ConfigService } from '@nestjs/config'
import { AuthError } from 'src/routes/auth/auth.error'
import { I18nService } from 'nestjs-i18n'
import { IOTPService } from 'src/shared/types/auth.types'
import { REDIS_SERVICE, EMAIL_SERVICE } from 'src/shared/constants/injection.tokens'
import { EmailService } from 'src/shared/services/email.service'
import { CookieService } from 'src/shared/services/cookie.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { v4 as uuidv4 } from 'uuid'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constants'
import { DeviceRepository } from 'src/shared/repositories/auth'

@Injectable()
export class OtpService implements IOTPService {
  private readonly logger = new Logger(OtpService.name)

  constructor(
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly jwtService: JwtService,
    private readonly i18nService: I18nService,
    private readonly configService: ConfigService,
    private readonly deviceRepository: DeviceRepository
  ) {}

  /**
   * Tạo mã OTP
   */
  generateOTP(length: number = OTP_LENGTH): string {
    const digits = '0123456789'
    let OTP = ''
    for (let i = 0; i < length; i++) {
      OTP += digits[Math.floor(Math.random() * 10)]
    }
    return OTP
  }

  /**
   * Tạo key cho Redis OTP
   */
  private getOtpKey(type: TypeOfVerificationCodeType, identifier: string): string {
    return RedisKeyManager.otpKey(type, identifier)
  }

  /**
   * Tạo key cho Redis SLT context
   */
  private getSltContextKey(jti: string): string {
    return RedisKeyManager.sltContextKey(jti)
  }

  /**
   * Tạo key cho cooldown của OTP
   */
  private getOtpLastSentKey(identifierForCooldown: string, purpose: TypeOfVerificationCodeType): string {
    return RedisKeyManager.otpLastSentKey(identifierForCooldown, purpose)
  }

  /**
   * Gửi OTP
   */
  async sendOTP(
    targetEmail: string,
    type: TypeOfVerificationCodeType,
    userIdForCooldownAndOtpData?: number,
    metadata?: Record<string, any>
  ): Promise<{ message: string; otpCode: string }> {
    const identifierForCooldown = userIdForCooldownAndOtpData
      ? `user:${userIdForCooldownAndOtpData}`
      : `email:${targetEmail}`
    const otpLastSentKey = this.getOtpLastSentKey(identifierForCooldown, type)

    const lastSentTimestamp = await this.redisService.get(otpLastSentKey)
    if (lastSentTimestamp) {
      const elapsedSeconds = (Date.now() - parseInt(lastSentTimestamp, 10)) / 1000
      const cooldown = this.configService.get<number>('security.otpCooldownSeconds', OTP_COOLDOWN_SECONDS)
      if (elapsedSeconds < cooldown) {
        const remainingSeconds = Math.ceil(cooldown - elapsedSeconds)
        this.logger.warn(
          `[sendOTP] OTP request for ${targetEmail} (type: ${type}) blocked due to cooldown. ${remainingSeconds}s remaining.`
        )
        throw AuthError.OTPSendingLimited()
      }
    }

    const otpCode = this.generateOTP()
    const otpKey = this.getOtpKey(type, targetEmail)
    const otpExpirySeconds = this.configService.get<number>('security.otpExpirySeconds', 300)

    const otpDataForRedis: Record<string, string | number> = {
      code: otpCode,
      attempts: 0,
      createdAt: Date.now(),
      ...(userIdForCooldownAndOtpData && { userId: userIdForCooldownAndOtpData }),
      ...(metadata && { metadata: JSON.stringify(metadata) })
    }

    await this.redisService.hset(otpKey, otpDataForRedis)
    await this.redisService.expire(otpKey, otpExpirySeconds)

    try {
      await this.emailService.sendOtpEmail({
        email: targetEmail,
        otpCode,
        otpType: type,
        ...(metadata?.emailTitle && { title: metadata.emailTitle })
      })
      this.logger.log(`[sendOTP] Email OTP ${otpCode} đã được gửi đến ${targetEmail} cho mục đích ${type}`)
    } catch (error) {
      this.logger.error(`[sendOTP] Lỗi gửi email OTP đến ${targetEmail}: ${error.message}`, error.stack)
      throw AuthError.InternalServerError('Failed to send OTP email.')
    }

    await this.redisService.set(otpLastSentKey, Date.now().toString(), 'EX', OTP_COOLDOWN_SECONDS)

    return { message: this.i18nService.t('auth.Auth.Otp.SentSuccessfully'), otpCode }
  }

  /**
   * Xác minh OTP
   */
  async verifyOTP(
    emailToVerifyAgainst: string,
    code: string,
    type: TypeOfVerificationCodeType,
    userIdForAudit?: number,
    ip?: string,
    userAgent?: string
  ): Promise<boolean> {
    if (!code || !emailToVerifyAgainst) {
      throw AuthError.InvalidOTP()
    }

    const otpKey = this.getOtpKey(type, emailToVerifyAgainst)
    const rawOtpData = await this.redisService.hgetall(otpKey)

    if (!rawOtpData || Object.keys(rawOtpData).length === 0) {
      this.logger.warn(`[verifyOTP] OTP data not found or expired for key: ${otpKey}`)
      throw AuthError.OTPExpired() // Or InvalidOTP if preferred when not found
    }

    // Parse rawOtpData into OtpData structure
    const otpData: OtpData = {
      code: rawOtpData.code,
      // Ensure attempts and createdAt are parsed correctly, even if they might be missing (though unlikely for a valid entry)
      attempts: parseInt(rawOtpData.attempts || '0', 10),
      createdAt: parseInt(rawOtpData.createdAt || '0', 10),
      userId: rawOtpData.userId ? parseInt(rawOtpData.userId, 10) : undefined,
      deviceId: rawOtpData.deviceId ? parseInt(rawOtpData.deviceId, 10) : undefined,
      metadata: rawOtpData.metadata ? JSON.parse(rawOtpData.metadata) : undefined
    }

    // Kiểm tra số lần thử tối đa từ config
    const maxAttempts = this.configService.get('security.otpMaxAttempts', 5) // Updated config key

    // Tăng số lần thử một cách an toàn bằng HINCRBY. Giá trị trả về là số lần thử SAU KHI tăng.
    const currentAttempts = await this.redisService.hincrby(otpKey, 'attempts', 1)

    if (currentAttempts > maxAttempts) {
      this.logger.warn(
        `[verifyOTP] Too many OTP attempts for key: ${otpKey}. Attempts: ${currentAttempts}, Max: ${maxAttempts}`
      )
      await this.redisService.del(otpKey) // Xóa OTP nếu vượt quá số lần thử
      throw AuthError.TooManyOTPAttempts()
    }

    // Kiểm tra mã OTP
    if (otpData.code !== code) {
      this.logger.warn(
        `[verifyOTP] Invalid OTP code for key: ${otpKey}. Expected: ${otpData.code}, Got: ${code}, Attempt: ${currentAttempts}/${maxAttempts}`
      )
      // Không cần xóa key ở đây nếu currentAttempts < maxAttempts, vì người dùng có thể thử lại
      if (currentAttempts >= maxAttempts) {
        await this.redisService.del(otpKey) // Xóa nếu đây là lần thử cuối cùng và thất bại
      }
      throw AuthError.InvalidOTP()
    }

    // Kiểm tra thời gian hiệu lực
    const now = Date.now()
    const otpCreatedAt = otpData.createdAt
    // Lấy OTP_EXPIRY_SECONDS từ config, với giá trị mặc định nếu không có
    const otpExpirySeconds = this.configService.get<number>(
      'security.otpExpirySeconds',
      this.configService.get<number>('OTP_EXPIRY_SECONDS', 300) // fallback for older constant name
    )
    const otpExpirationTimeMs = otpExpirySeconds * 1000

    if (now - otpCreatedAt > otpExpirationTimeMs) {
      this.logger.warn(`[verifyOTP] OTP expired for key: ${otpKey}. Created: ${otpCreatedAt}, Now: ${now}`)
      await this.redisService.del(otpKey)
      throw AuthError.OTPExpired()
    }

    // Xác minh thành công, xóa mã OTP
    this.logger.log(`[verifyOTP] OTP ${code} verified successfully for key: ${otpKey}`)
    await this.redisService.del(otpKey)

    return true
  }

  /**
   * Khởi tạo OTP và SLT cookie
   */
  async initiateOtpWithSltCookie(payload: {
    email: string
    userId: number
    deviceId: number
    ipAddress: string
    userAgent: string
    purpose: TypeOfVerificationCodeType
    metadata?: Record<string, any>
  }): Promise<string> {
    this.logger.debug(
      `[initiateOtpWithSltCookie] Initializing OTP for email ${payload.email} with purpose ${payload.purpose}`
    )
    const { email, userId, deviceId, ipAddress, userAgent, purpose, metadata } = payload
    const effectiveUserIdForOtp = userId // Use actual userId for OTP cooldown and data association

    // Conditionally send OTP
    // Do NOT send an email OTP if this is a 2FA (TOTP) verification step.
    // The user will be prompted for their TOTP code from their authenticator app.
    const shouldSendEmailOtp = !(
      purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_2FA &&
      metadata?.twoFactorMethod === TwoFactorMethodType.TOTP
    )

    if (shouldSendEmailOtp) {
      this.logger.debug(`[initiateOtpWithSltCookie] Sending OTP for purpose: ${purpose} and email: ${email}`)
      await this.sendOTP(email, purpose, effectiveUserIdForOtp, metadata)
    } else {
      this.logger.debug(`[initiateOtpWithSltCookie] Skipping email OTP send for 2FA/TOTP purpose: ${purpose}`)
    }

    // Tạo JTI (JWT ID) duy nhất cho SLT JWT
    const sltJti = `slt_${Date.now()}_${uuidv4().substring(0, 8)}`
    this.logger.debug(`[initiateOtpWithSltCookie] Generated JTI: ${sltJti}`)

    // Tạo payload cho SLT JWT
    const sltJwtPayload: SltJwtPayload = {
      jti: sltJti,
      sub: userId,
      pur: purpose
    }

    const sltToken = this.jwtService.sign(sltJwtPayload, {
      secret: this.configService.get<string>('SLT_JWT_SECRET'),
      expiresIn: `${this.configService.get<number>('SLT_JWT_EXPIRES_IN_MINUTES', SLT_EXPIRY_SECONDS / 60)}m`
    })

    // Chuẩn bị context để lưu vào Redis
    const sltContextData: SltContextData = {
      userId,
      deviceId,
      ipAddress,
      userAgent,
      purpose,
      sltJwtExp: sltJwtPayload.exp || Math.floor(Date.now() / 1000) + SLT_EXPIRY_SECONDS,
      sltJwtCreatedAt: Math.floor(Date.now() / 1000),
      finalized: '0',
      attempts: 0,
      metadata,
      email // Include email in SLT context
    }

    // Lưu SLT context vào Redis
    const sltContextKey = this.getSltContextKey(sltJti)
    try {
      // Chuẩn bị dữ liệu để lưu vào Redis
      const redisData: Record<string, string> = {
        finalized: sltContextData.finalized,
        deviceId: sltContextData.deviceId.toString(),
        ipAddress: sltContextData.ipAddress,
        userAgent: sltContextData.userAgent,
        sltJwtExp: sltContextData.sltJwtExp.toString(),
        userId: sltContextData.userId.toString(),
        attempts: sltContextData.attempts.toString(),
        ...(sltContextData.metadata && { metadata: JSON.stringify(sltContextData.metadata) }),
        purpose: sltContextData.purpose,
        sltJwtCreatedAt: sltContextData.sltJwtCreatedAt.toString(),
        ...(sltContextData.email && { email: sltContextData.email })
      }

      await this.redisService.hset(
        sltContextKey,
        redisData,
        undefined // value is part of fields in this case
      )
      await this.redisService.expire(sltContextKey, SLT_EXPIRY_SECONDS)
      this.logger.debug(
        `[initiateOtpWithSltCookie] SLT context saved to Redis with key ${sltContextKey} and TTL ${SLT_EXPIRY_SECONDS}s`
      )
      this.logger.debug(`[initiateOtpWithSltCookie] Verification - Redis data saved: ${JSON.stringify(redisData)}`)
    } catch (error) {
      this.logger.error(
        `[initiateOtpWithSltCookie] Failed to save SLT context to Redis for key ${sltContextKey}: ${error.message}`,
        error.stack
      )
      throw AuthError.InternalServerError('Failed to save SLT context')
    }

    this.logger.debug(`[initiateOtpWithSltCookie] SLT JWT signed successfully, length: ${sltToken.length}`)
    return sltToken
  }

  /**
   * Xác minh SLT từ cookie và lấy context
   */
  async validateSltFromCookieAndGetContext(
    sltCookieValue: string,
    currentIpAddress: string,
    currentUserAgent: string,
    expectedPurpose?: TypeOfVerificationCodeType
  ): Promise<SltContextData & { sltJti: string }> {
    this.logger.debug(
      `[validateSltFromCookieAndGetContext] Validating SLT cookie, token length: ${sltCookieValue.length}`
    )
    let decodedSltJwt: SltJwtPayload
    try {
      decodedSltJwt = await this.jwtService.verifyAsync<SltJwtPayload>(sltCookieValue, {
        secret: this.configService.get<string>('SLT_JWT_SECRET')
      })
      this.logger.debug(
        `[validateSltFromCookieAndGetContext] JWT verified successfully, JTI: ${decodedSltJwt.jti}, Purpose: ${decodedSltJwt.pur}`
      )
    } catch (error) {
      this.logger.error(`[validateSltFromCookieAndGetContext] Error validating SLT cookie: ${error.message}`, {
        stack: error.stack?.split('\n')
      })
      if (error.name === 'TokenExpiredError') {
        throw AuthError.SLTExpired()
      } else if (error.name === 'JsonWebTokenError') {
        // Catches invalid signature, malformed token etc.
        throw AuthError.SLTCookieMissing() // Or a more specific error if preferred
      }
      throw AuthError.InternalServerError('Failed to validate SLT cookie')
    }

    const sltJti = decodedSltJwt.jti

    // Kiểm tra purpose nếu có expected purpose
    if (expectedPurpose && decodedSltJwt.pur !== expectedPurpose) {
      this.logger.warn(
        `[validateSltFromCookieAndGetContext] Invalid purpose, expected: ${expectedPurpose}, got: ${decodedSltJwt.pur}`
      )
      throw AuthError.SLTInvalidPurpose()
    }

    // Lấy SLT context từ Redis
    const sltContextKey = this.getSltContextKey(sltJti)
    this.logger.debug(`[validateSltFromCookieAndGetContext] Fetching SLT context from Redis with key: ${sltContextKey}`)

    const sltContextData = await this.redisService.hgetall(sltContextKey)
    this.logger.debug(`[validateSltFromCookieAndGetContext] Redis data fetched: ${JSON.stringify(sltContextData)}`)

    if (!sltContextData || Object.keys(sltContextData).length === 0) {
      this.logger.error('[validateSltFromCookieAndGetContext] SLT context data not found in Redis or expired')
      throw AuthError.SLTExpired()
    }

    // Chuyển đổi kiểu dữ liệu từ string sang kiểu dữ liệu gốc
    const sltContext: SltContextData & { sltJti: string } = {
      userId: parseInt(sltContextData.userId, 10),
      deviceId: parseInt(sltContextData.deviceId, 10),
      ipAddress: sltContextData.ipAddress,
      userAgent: sltContextData.userAgent,
      purpose: sltContextData.purpose as TypeOfVerificationCodeType,
      sltJwtExp: parseInt(sltContextData.sltJwtExp, 10),
      sltJwtCreatedAt: parseInt(sltContextData.sltJwtCreatedAt, 10),
      finalized: sltContextData.finalized as '0' | '1',
      attempts: parseInt(sltContextData.attempts, 10),
      metadata: sltContextData.metadata ? JSON.parse(sltContextData.metadata) : undefined,
      email: sltContextData.email,
      sltJti: sltJti
    }

    this.logger.debug(
      `[validateSltFromCookieAndGetContext] SLT context processed successfully: ${JSON.stringify({
        ...sltContext,
        userId: typeof sltContext.userId === 'number' ? sltContext.userId : 'Invalid type',
        deviceId: typeof sltContext.deviceId === 'number' ? sltContext.deviceId : 'Invalid type'
      })}`
    )

    return sltContext
  }

  /**
   * Cập nhật SLT context
   */
  async updateSltContext(jti: string, updateData: Partial<SltContextData>): Promise<void> {
    const sltContextKey = this.getSltContextKey(jti)
    this.logger.debug(
      `[updateSltContext] Updating SLT context for JTI: ${jti} with data: ${JSON.stringify(updateData)}`
    )

    // Chuyển đổi metadata thành string nếu cần
    if (updateData.metadata) {
      updateData.metadata = JSON.stringify(updateData.metadata) as any
    }

    try {
      await this.redisService.hset(sltContextKey, updateData as any)
      this.logger.debug(`[updateSltContext] SLT context updated successfully for JTI: ${jti}`)
    } catch (error) {
      this.logger.error(`[updateSltContext] Failed to update SLT context in Redis: ${error.message}`)
      throw error
    }
  }

  /**
   * Đánh dấu SLT đã hoàn tất
   */
  async finalizeSlt(sltJti: string): Promise<void> {
    await this.updateSltContext(sltJti, { finalized: '1' })
  }

  /**
   * Tăng số lần thử của SLT
   */
  async incrementSltAttempts(sltJti: string): Promise<number> {
    const sltContextKey = this.getSltContextKey(sltJti)
    const attempts = await this.redisService.hincrby(sltContextKey, 'attempts', 1)
    return attempts
  }

  private getTrustExpirationDate(): Date {
    const trustDurationDays = this.configService.get<number>('security.deviceTrustDurationDays', 30)
    const expirationDate = new Date()
    expirationDate.setDate(expirationDate.getDate() + trustDurationDays)
    return expirationDate
  }

  /**
   * Xác minh OTP trong SLT context
   */
  async verifySltOtpStage(
    sltCookieValue: string,
    otpCode: string,
    currentIpAddress: string,
    currentUserAgent: string
  ): Promise<SltContextData & { sltJti: string }> {
    this.logger.debug(`[verifySltOtpStage] Verifying SLT OTP for IP: ${currentIpAddress}`)
    const sltContext = await this.validateSltFromCookieAndGetContext(sltCookieValue, currentIpAddress, currentUserAgent)

    if (!sltContext.email) {
      this.logger.error('[verifySltOtpStage] Email missing in SLT context after validation.')
      throw AuthError.EmailMissingInSltContext()
    }

    const isOtpValid = await this.verifyOTP(
      sltContext.email,
      otpCode,
      sltContext.purpose,
      sltContext.userId,
      currentIpAddress,
      currentUserAgent
    )

    if (!isOtpValid) {
      this.logger.warn(
        `[verifySltOtpStage] OTP verification failed for email: ${sltContext.email}, purpose: ${sltContext.purpose}`
      )
      throw AuthError.InvalidOTP()
    }

    if (
      sltContext.purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP &&
      sltContext.metadata?.rememberMe === true &&
      sltContext.deviceId
    ) {
      try {
        this.logger.debug(
          `[verifySltOtpStage] Trusting device ${sltContext.deviceId} for user ${sltContext.userId} due to rememberMe.`
        )
        await this.deviceRepository.updateDeviceTrustStatus(sltContext.deviceId, true, this.getTrustExpirationDate())
      } catch (error) {
        this.logger.error(
          `[verifySltOtpStage] Error trusting device ${sltContext.deviceId}: ${error.message}`,
          error.stack
        )
      }
    }

    this.logger.debug(
      `[verifySltOtpStage] SLT OTP verified successfully for ${sltContext.email}, purpose ${sltContext.purpose}`
    )
    return sltContext
  }
}
