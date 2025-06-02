import { Injectable, Logger, Inject } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import {
  TypeOfVerificationCodeType,
  MAX_OTP_ATTEMPTS,
  OTP_EXPIRATION_TIME,
  OTP_LENGTH
} from 'src/routes/auth/constants/auth.constants'
import { OtpData, SltContextData, SltJwtPayload } from 'src/routes/auth/auth.types'
import { ConfigService } from '@nestjs/config'
import { AuthError } from 'src/routes/auth/auth.error'
import { I18nService } from 'nestjs-i18n'
import { IOTPService } from 'src/shared/types/auth.types'
import { REDIS_SERVICE, EMAIL_SERVICE } from 'src/shared/constants/injection.tokens'
import { EmailService } from 'src/shared/services/email.service'

@Injectable()
export class OtpService implements IOTPService {
  private readonly logger = new Logger(OtpService.name)

  constructor(
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly jwtService: JwtService,
    private readonly i18nService: I18nService,
    private readonly configService: ConfigService
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
    return `otp:${type}:${identifier}`
  }

  /**
   * Tạo key cho Redis SLT context
   */
  private getSltContextKey(jti: string): string {
    const key = `slt:context:${jti}`
    this.logger.debug(`[getSltContextKey] Generated Redis key: ${key}`)
    return key
  }

  /**
   * Tạo key cho Redis SLT blacklist
   */
  private getSltBlacklistKey(jti: string): string {
    return `slt:blacklist:${jti}`
  }

  /**
   * Tạo key cho cooldown của OTP
   */
  private getOtpLastSentKey(identifierForCooldown: string, purpose: TypeOfVerificationCodeType): string {
    return `otp:cooldown:${purpose}:${identifierForCooldown}`
  }

  /**
   * Gửi OTP
   */
  async sendOTP(
    targetEmail: string,
    type: TypeOfVerificationCodeType,
    userIdForCooldownAndOtpData?: number
  ): Promise<{ message: string; otpCode: string }> {
    // Tạo key cho Redis
    const otpKey = this.getOtpKey(type, targetEmail)

    // Tạo mã OTP
    const otpCode = this.generateOTP()

    // Tạo OTP data
    const otpData: OtpData = {
      code: otpCode,
      attempts: 0,
      createdAt: Date.now(),
      userId: userIdForCooldownAndOtpData
    }

    // Lưu OTP vào Redis
    await this.redisService.set(otpKey, JSON.stringify(otpData), 'EX', OTP_EXPIRATION_TIME / 1000)

    // Gửi email OTP
    try {
      await this.emailService.sendOtpEmail({
        email: targetEmail,
        otpCode: otpCode,
        otpType: type
      })
    } catch (error) {
      this.logger.error(`Chi tiết lỗi gửi email: ${JSON.stringify(error)}`, error.stack)
      // Vẫn trả về thành công nếu đã tạo OTP
    }

    return {
      message: await this.i18nService.translate('Auth.Otp.SentSuccessfully'),
      otpCode // Trong môi trường production, không nên trả về mã OTP
    }
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
    // Tạo key cho Redis
    const otpKey = this.getOtpKey(type, emailToVerifyAgainst)

    // Lấy dữ liệu OTP từ Redis
    const otpDataStr = await this.redisService.get(otpKey)
    if (!otpDataStr) {
      throw AuthError.OTPExpired()
    }

    // Parse dữ liệu OTP
    const otpData = JSON.parse(otpDataStr) as OtpData

    // Kiểm tra số lần thử
    if (otpData.attempts >= MAX_OTP_ATTEMPTS) {
      // Xóa OTP nếu vượt quá số lần thử
      await this.redisService.del(otpKey)
      throw AuthError.TooManyOTPAttempts()
    }

    // Tăng số lần thử
    otpData.attempts += 1
    await this.redisService.set(
      otpKey,
      JSON.stringify(otpData),
      'EX',
      OTP_EXPIRATION_TIME / 1000 - Math.floor((Date.now() - otpData.createdAt) / 1000)
    )

    // Kiểm tra mã OTP
    if (otpData.code !== code) {
      throw AuthError.InvalidOTP()
    }

    // Kiểm tra hết hạn
    if (Date.now() - otpData.createdAt > OTP_EXPIRATION_TIME) {
      throw AuthError.OTPExpired()
    }

    // Xóa OTP sau khi xác minh thành công
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
    const { email, userId, deviceId, ipAddress, userAgent, purpose, metadata } = payload

    this.logger.debug(`[initiateOtpWithSltCookie] Initializing OTP for email ${email} with purpose ${purpose}`)

    // Gửi OTP đến email
    await this.sendOTP(email, purpose, userId)
    this.logger.debug(`[initiateOtpWithSltCookie] OTP sent successfully for ${email}`)

    // Tạo JTI (JWT ID)
    const jti = `slt_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`
    this.logger.debug(`[initiateOtpWithSltCookie] Generated JTI: ${jti}`)

    // Tạo SLT JWT payload
    const sltJwtPayload: SltJwtPayload = {
      jti,
      sub: userId,
      pur: purpose
    }
    this.logger.debug(`[initiateOtpWithSltCookie] SLT JWT payload: ${JSON.stringify(sltJwtPayload)}`)

    // Tính thời gian hết hạn (5 phút)
    const expiresInSeconds = 300 // 5 phút
    const expirationTime = Math.floor(Date.now() / 1000) + expiresInSeconds

    // Tạo SLT context
    const sltContext: SltContextData = {
      userId,
      deviceId,
      ipAddress,
      userAgent,
      purpose,
      sltJwtExp: expirationTime,
      sltJwtCreatedAt: Date.now(),
      finalized: '0',
      attempts: 0,
      metadata,
      email
    }
    this.logger.debug(`[initiateOtpWithSltCookie] SLT context created: ${JSON.stringify(sltContext)}`)

    // Lưu SLT context vào Redis
    const sltContextKey = this.getSltContextKey(jti)
    try {
      // Chuẩn bị dữ liệu để lưu vào Redis
      const contextForRedis = {
        ...sltContext,
        userId: String(userId), // Chuyển đổi thành string trước khi lưu
        deviceId: String(deviceId), // Chuyển đổi thành string trước khi lưu
        metadata: metadata ? JSON.stringify(metadata) : undefined
      }

      await this.redisService.hset(sltContextKey, contextForRedis as any)
      const ttl = expiresInSeconds + 60 // Thêm 1 phút buffer
      await this.redisService.expire(sltContextKey, ttl)
      this.logger.debug(
        `[initiateOtpWithSltCookie] SLT context saved to Redis with key ${sltContextKey} and TTL ${ttl}s`
      )

      // Kiểm tra xem dữ liệu đã lưu thành công chưa
      const savedContext = await this.redisService.hgetall(sltContextKey)
      this.logger.debug(`[initiateOtpWithSltCookie] Verification - Redis data saved: ${JSON.stringify(savedContext)}`)
    } catch (error) {
      this.logger.error(`[initiateOtpWithSltCookie] Failed to save SLT context to Redis: ${error.message}`)
      throw error
    }

    // Sign SLT JWT
    let sltJwt
    try {
      sltJwt = this.jwtService.sign(sltJwtPayload, {
        secret: this.configService.get('SLT_JWT_SECRET'),
        expiresIn: expiresInSeconds // Sử dụng cùng thời gian hết hạn đã tính
      })
      this.logger.debug(`[initiateOtpWithSltCookie] SLT JWT signed successfully, length: ${sltJwt.length}`)
    } catch (error) {
      this.logger.error(`[initiateOtpWithSltCookie] Failed to sign SLT JWT: ${error.message}`)
      throw error
    }

    return sltJwt
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
      `[validateSltFromCookieAndGetContext] Validating SLT cookie, token length: ${sltCookieValue?.length || 0}`
    )

    try {
      // Kiểm tra giá trị cookie
      if (!sltCookieValue || sltCookieValue.trim() === '') {
        this.logger.error('[validateSltFromCookieAndGetContext] SLT cookie value is empty or invalid')
        throw AuthError.SLTCookieMissing()
      }

      // Xác minh SLT JWT
      this.logger.debug(
        `[validateSltFromCookieAndGetContext] Verifying JWT token with secret: ${this.configService.get('SLT_JWT_SECRET') ? 'Available' : 'Missing'}`
      )

      const payload = await this.jwtService.verifyAsync<SltJwtPayload>(sltCookieValue, {
        secret: this.configService.get('SLT_JWT_SECRET')
      })
      const { jti, pur: purpose } = payload
      this.logger.debug(
        `[validateSltFromCookieAndGetContext] JWT verified successfully, JTI: ${jti}, Purpose: ${purpose}`
      )

      // Kiểm tra purpose nếu có expected purpose
      if (expectedPurpose && purpose !== expectedPurpose) {
        this.logger.warn(
          `[validateSltFromCookieAndGetContext] Invalid purpose, expected: ${expectedPurpose}, got: ${purpose}`
        )
        throw AuthError.SLTInvalidPurpose()
      }

      // Lấy SLT context từ Redis
      const sltContextKey = this.getSltContextKey(jti)
      this.logger.debug(
        `[validateSltFromCookieAndGetContext] Fetching SLT context from Redis with key: ${sltContextKey}`
      )

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
        sltJti: jti
      }

      this.logger.debug(
        `[validateSltFromCookieAndGetContext] SLT context processed successfully: ${JSON.stringify({
          ...sltContext,
          userId: typeof sltContext.userId === 'number' ? sltContext.userId : 'Invalid type',
          deviceId: typeof sltContext.deviceId === 'number' ? sltContext.deviceId : 'Invalid type'
        })}`
      )

      return sltContext
    } catch (error) {
      this.logger.error(
        `[validateSltFromCookieAndGetContext] Error validating SLT cookie: ${error.message}`,
        error.stack
      )
      throw error
    }
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

  /**
   * Xác minh OTP trong SLT context
   */
  async verifySltOtpStage(
    sltCookieValue: string,
    otpCode: string,
    currentIpAddress: string,
    currentUserAgent: string
  ): Promise<SltContextData & { sltJti: string }> {
    // Xác minh SLT và lấy context
    const sltContext = await this.validateSltFromCookieAndGetContext(sltCookieValue, currentIpAddress, currentUserAgent)

    // Xác minh OTP
    await this.verifyOTP(
      sltContext.email || '',
      otpCode,
      sltContext.purpose,
      sltContext.userId,
      currentIpAddress,
      currentUserAgent
    )

    // Cập nhật SLT context thành đã xác minh
    await this.updateSltContext(sltContext.sltJti, { finalized: '1' })

    // Trả về context sau khi xác minh
    return sltContext
  }
}
