import { Injectable, Logger, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import * as speakeasy from 'speakeasy'
import * as QRCode from 'qrcode'
import { Response } from 'express'
import { I18nService } from 'nestjs-i18n'
import { OtpService } from '../otp/otp.service'
import { HashingService } from 'src/shared/services/hashing.service'
import {
  TypeOfVerificationCode,
  TwoFactorMethodType,
  TypeOfVerificationCodeType
} from 'src/shared/constants/auth.constants'
import { ICookieService, ITokenService } from 'src/shared/types/auth.types'
import { COOKIE_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { AuthError } from 'src/routes/auth/auth.error'
import { v4 as uuidv4 } from 'uuid'
import { TwoFactorConfirmSetupDto } from './two-factor.dto'
import { UserAuthRepository, RecoveryCodeRepository, DeviceRepository } from 'src/shared/repositories/auth'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { PickedUserProfileResponseType } from 'src/shared/dtos/user.dto'
import { JwtService } from '@nestjs/jwt'

@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name)

  constructor(
    private readonly configService: ConfigService,
    private readonly i18nService: I18nService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly otpService: OtpService,
    private readonly hashingService: HashingService,
    private readonly userAuthRepository: UserAuthRepository,
    private readonly recoveryCodeRepository: RecoveryCodeRepository,
    private readonly deviceRepository: DeviceRepository,
    @Inject(RedisService) private readonly redisService: RedisService,
    private readonly jwtService: JwtService
  ) {}

  /**
   * Tạo TOTP
   */
  private createTOTP(email: string, secret?: string) {
    const secretKey =
      secret ||
      speakeasy.generateSecret({
        length: 20,
        name: `ShopSifu:${email}`,
        issuer: 'ShopSifu'
      })

    const otpauthUrl = speakeasy.otpauthURL({
      secret: secretKey.ascii,
      label: `ShopSifu:${email}`,
      issuer: 'ShopSifu',
      encoding: 'ascii'
    })

    return {
      secret: secretKey.base32,
      otpauthUrl
    }
  }

  /**
   * Tạo mã khôi phục
   */
  private generateRecoveryCodes(count: number = 8): string[] {
    const codes: string[] = []
    for (let i = 0; i < count; i++) {
      // Tạo mã khôi phục với 4 nhóm, mỗi nhóm 4 ký tự
      const code = [
        this.generateRandomString(4),
        this.generateRandomString(4),
        this.generateRandomString(4),
        this.generateRandomString(4)
      ].join('-')
      codes.push(code)
    }
    return codes
  }

  /**
   * Tạo chuỗi ngẫu nhiên
   */
  private generateRandomString(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    let result = ''
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length))
    }
    return result
  }

  /**
   * Xác minh TOTP
   */
  private verifyTOTP(secret: string, token: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 1 // Cho phép mã trước/sau 1 chu kỳ (30 giây trước/sau)
    })
  }

  /**
   * Thiết lập 2FA
   */
  async setupTwoFactor(
    userId: number,
    deviceId: number,
    ip: string,
    userAgent: string,
    res: Response
  ): Promise<{ secret: string; uri: string }> {
    this.logger.debug(`Setting up 2FA for user ${userId} from device ${deviceId}`)

    // Tìm user
    const user = await this.userAuthRepository.findById(userId)

    if (!user) {
      this.logger.error(`User with ID ${userId} not found when setting up 2FA`)
      throw AuthError.EmailNotFound()
    }

    // Kiểm tra user đã bật 2FA chưa
    if (user.twoFactorEnabled) {
      this.logger.warn(`User ${userId} already has 2FA enabled`)
      throw AuthError.TOTPAlreadyEnabled()
    }

    try {
      // Tạo secret và uri cho TOTP
      const { secret, otpauthUrl } = this.createTOTP(user.email)
      this.logger.debug(`TOTP secret generated for user ${userId}`)

      // Tạo QR code
      const qrCodeUri = await QRCode.toDataURL(otpauthUrl)
      this.logger.debug(`QR code URI generated, length: ${qrCodeUri.length}`)

      // Tạo SLT để lưu trữ thông tin giữa các bước
      const sltJwtPayload = {
        jti: `slt_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`,
        sub: user.id,
        pur: TypeOfVerificationCode.SETUP_2FA
      }

      const sltJwt = this.tokenService.signShortLivedToken(sltJwtPayload)

      // Lưu context vào Redis
      const contextKey = RedisKeyManager.sltContextKey(sltJwtPayload.jti)
      const contextData = {
        userId: String(user.id),
        deviceId: String(deviceId),
        ipAddress: ip,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.SETUP_2FA,
        sltJwtExp: String(Math.floor(Date.now() / 1000) + 300), // 5 phút
        sltJwtCreatedAt: String(Date.now()),
        finalized: '0',
        attempts: '0',
        metadata: JSON.stringify({
          secret,
          twoFactorMethod: TwoFactorMethodType.TOTP
        })
      }

      await this.redisService.hset(contextKey, contextData as any)
      await this.redisService.expire(contextKey, 360) // 6 phút

      // Set SLT cookie
      this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.SETUP_2FA)
      this.logger.debug(`SLT cookie set for user ${userId} for 2FA setup confirmation (no email OTP sent)`)

      // Xóa các SLT token khác nếu có (ví dụ: từ flow trước đó)
      const cookies = res.getHeader('Set-Cookie') as string[]
      if (cookies && cookies.length > 1) {
        this.logger.debug(`[setupTwoFactor] Multiple Set-Cookie headers found, ensuring only new SLT is set`)
      }

      return {
        secret,
        uri: qrCodeUri
      }
    } catch (error) {
      this.logger.error(`Error during 2FA setup for user ${userId}: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Xác nhận thiết lập 2FA
   */
  async confirmTwoFactorSetup(
    userId: number,
    sltCookieValue: string,
    totpCode: string,
    ip: string,
    userAgent: string,
    res: Response
  ): Promise<{ message: string; recoveryCodes: string[] }> {
    // Xác minh SLT và lấy context
    const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
      sltCookieValue,
      ip,
      userAgent,
      TypeOfVerificationCode.SETUP_2FA
    )

    const secret = sltContext.metadata?.secret
    const twoFactorMethod = sltContext.metadata?.twoFactorMethod

    if (!secret || !twoFactorMethod) {
      throw AuthError.SLTInvalidPurpose()
    }

    // Tìm user
    const user = await this.userAuthRepository.findById(userId)

    if (!user) {
      throw AuthError.EmailNotFound()
    }

    // Xác minh TOTP
    const isValid = this.verifyTOTP(secret, totpCode)

    if (!isValid) {
      throw AuthError.InvalidTOTP()
    }

    // Tạo mã khôi phục
    const recoveryCodes = this.generateRecoveryCodes()
    const hashedRecoveryCodes = await Promise.all(
      recoveryCodes.map(async (code) => await this.hashingService.hash(code))
    )

    // Lưu mã khôi phục
    await this.recoveryCodeRepository.createRecoveryCodes(userId, hashedRecoveryCodes)

    // Cập nhật user với 2FA
    await this.userAuthRepository.updateTwoFactorSettings(userId, {
      twoFactorEnabled: true,
      twoFactorSecret: secret,
      twoFactorMethod: TwoFactorMethodType.TOTP,
      twoFactorVerifiedAt: new Date()
    })

    // Xóa SLT cookie
    this.cookieService.clearSltCookie(res)

    return {
      message: await this.i18nService.t('auth.Auth.2FA.Setup.Success'),
      recoveryCodes
    }
  }

  /**
   * Xác minh 2FA
   */
  async verifyTwoFactor(
    code: string,
    rememberMe: boolean,
    sltCookieValue: string,
    ip: string,
    userAgent: string,
    method: string = 'TOTP'
  ): Promise<{
    message: string
    requiresDeviceVerification?: boolean
    verifiedMethod: string
    user?: {
      id: number
      email: string
      roleName: string
      isDeviceTrustedInSession: boolean
      userProfile: PickedUserProfileResponseType | null
    }
    purpose?: TypeOfVerificationCodeType
    userId?: number
    sltDeviceId?: number
    metadata?: any
  }> {
    // Xác thực SLT token và lấy context
    const sltContext = await this.otpService.validateSltFromCookieAndGetContext(sltCookieValue, ip, userAgent)

    this.logger.debug(`[verifyTwoFactor] Verifying 2FA for user ${sltContext.userId} (from SLT) with method ${method}`)

    if (!sltContext.userId) {
      this.logger.warn(`[verifyTwoFactor] User ID missing in SLT context for JTI: ${sltContext.sltJti}`)
      throw AuthError.SLTInvalidPurpose() // Hoặc một lỗi cụ thể hơn
    }

    // Tìm user từ sltContext.userId
    const user = await this.userAuthRepository.findById(sltContext.userId)
    if (!user) {
      this.logger.warn(`[verifyTwoFactor] User not found with ID: ${sltContext.userId} from SLT context`)
      throw AuthError.EmailNotFound()
    }

    let isValid = false
    const verifiedMethodUpper = method.toUpperCase() // Chuẩn hóa method và dùng const

    if (verifiedMethodUpper === TwoFactorMethodType.TOTP.toString()) {
      if (!user.twoFactorEnabled || !user.twoFactorSecret) {
        this.logger.error(`[verifyTwoFactor] 2FA (TOTP) not enabled or secret missing for user ${user.id}`)
        throw AuthError.TOTPNotEnabled()
      }
      isValid = this.verifyTOTP(user.twoFactorSecret, code)
      if (!isValid) {
        throw AuthError.InvalidTOTP()
      }
    } else if (verifiedMethodUpper === TwoFactorMethodType.RECOVERY.toString()) {
      // Sửa thành RECOVERY
      isValid = await this.verifyRecoveryCode(sltContext.userId, code)
      if (!isValid) {
        throw AuthError.InvalidRecoveryCode()
      }
    } else {
      this.logger.warn(`[verifyTwoFactor] Invalid 2FA method: ${method}`)
      throw AuthError.InvalidTwoFactorMethod()
    }

    this.logger.debug(
      `[verifyTwoFactor] Code verification successful for user ${sltContext.userId} using method ${verifiedMethodUpper}`
    )

    // Đánh dấu SLT là đã finalized NGAY SAU KHI mã được xác minh thành công
    await this.otpService.finalizeSlt(sltContext.sltJti)
    this.logger.debug(`[verifyTwoFactor] SLT finalized for JTI: ${sltContext.sltJti}`)

    // Sau khi xác minh thành công, nếu mục đích là LOGIN_UNTRUSTED_DEVICE_2FA và rememberMe là true, thì trust device
    if (
      sltContext.purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_2FA &&
      rememberMe === true &&
      sltContext.deviceId
    ) {
      try {
        this.logger.debug(
          `[verifyTwoFactor] Trusting device ${sltContext.deviceId} for user ${sltContext.userId} due to rememberMe.`
        )
        await this.deviceRepository.updateDeviceTrustStatus(
          sltContext.deviceId,
          true,
          this.getTrustExpirationDate() // Không cần await vì hàm này không còn là async
        )
      } catch (error) {
        this.logger.error(
          `[verifyTwoFactor] Error trusting device ${sltContext.deviceId}: ${error.message}`,
          error.stack
        )
        // Không ném lỗi ở đây để user vẫn có thể đăng nhập, nhưng ghi log lại
      }
    }

    // Chuẩn bị thông tin user để trả về nếu cần cho LOGIN_UNTRUSTED_DEVICE_2FA
    // UserAuthRepository.findById đã bao gồm role và userProfile
    const userResponseForLogin = {
      id: user.id,
      email: user.email,
      roleName: user.role.name,
      isDeviceTrustedInSession:
        sltContext.deviceId && rememberMe && sltContext.purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_2FA
          ? true
          : await this.deviceRepository.isDeviceTrustValid(sltContext.deviceId || 0),
      userProfile: user.userProfile
        ? {
            firstName: user.userProfile.firstName,
            lastName: user.userProfile.lastName,
            username: user.userProfile.username,
            avatar: user.userProfile.avatar
          }
        : null
    }

    // Nếu mục đích là đăng nhập 2FA, controller sẽ gọi finalizeLogin dựa trên thông tin này
    if (sltContext.purpose === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_2FA) {
      return {
        message: await this.i18nService.t('auth.Auth.2FA.Verify.Success'),
        verifiedMethod: verifiedMethodUpper,
        user: userResponseForLogin,
        purpose: sltContext.purpose,
        userId: sltContext.userId,
        sltDeviceId: sltContext.deviceId,
        metadata: sltContext.metadata
      }
    }

    // Xử lý các mục đích khác (ví dụ: revoke session, disable 2fa)
    // Trả về thông tin cần thiết để controller tiếp tục xử lý
    return {
      message: await this.i18nService.t('auth.Auth.2FA.Verify.Success'),
      verifiedMethod: verifiedMethodUpper,
      purpose: sltContext.purpose,
      userId: sltContext.userId,
      sltDeviceId: sltContext.deviceId,
      metadata: sltContext.metadata
      // Không trả về user object ở đây vì mục đích không phải là đăng nhập hoàn chỉnh
    }
  }

  /**
   * Xác minh mã khôi phục
   */
  private async verifyRecoveryCode(userId: number, code: string): Promise<boolean> {
    // Lấy tất cả mã khôi phục chưa sử dụng
    const recoveryCodes = await this.recoveryCodeRepository.findUnusedRecoveryCodesByUserId(userId)

    // Kiểm tra từng mã
    for (const recoveryCode of recoveryCodes) {
      const isMatch = await this.hashingService.compare(code, recoveryCode.code)
      if (isMatch) {
        // Đánh dấu mã đã được sử dụng
        await this.recoveryCodeRepository.markRecoveryCodeAsUsed(recoveryCode.id)
        return true
      }
    }

    return false
  }

  /**
   * Tắt 2FA
   */
  async disableTwoFactor(
    userId: number,
    code: string,
    method?: 'TOTP' | 'RECOVERY_CODE' | 'PASSWORD',
    ip?: string,
    userAgent?: string,
    sltCookieValue?: string
  ): Promise<{ message: string }> {
    // Tìm user
    const user = await this.userAuthRepository.findById(userId)

    if (!user) {
      throw AuthError.EmailNotFound()
    }

    if (!user.twoFactorEnabled) {
      throw AuthError.TOTPNotEnabled()
    }

    let isVerified = false

    // Xác minh dựa trên phương thức
    if (method === 'TOTP' && user.twoFactorSecret) {
      // Xác minh bằng TOTP
      isVerified = this.verifyTOTP(user.twoFactorSecret, code)
    } else if (method === 'RECOVERY_CODE') {
      // Xác minh bằng mã khôi phục
      isVerified = await this.verifyRecoveryCode(userId, code)
    } else if (method === 'PASSWORD') {
      // Xác minh bằng mật khẩu
      isVerified = await this.hashingService.compare(code, user.password)
    } else if (sltCookieValue) {
      // Xác minh bằng SLT token
      try {
        const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
          sltCookieValue,
          ip || '',
          userAgent || '',
          TypeOfVerificationCode.DISABLE_2FA
        )

        if (sltContext.finalized === '1') {
          isVerified = true
        }
      } catch (error) {
        isVerified = false
      }
    } else {
      // Mặc định là TOTP nếu user có twoFactorSecret
      if (user.twoFactorSecret) {
        isVerified = this.verifyTOTP(user.twoFactorSecret, code)
      }
    }

    if (!isVerified) {
      throw AuthError.InvalidTOTP()
    }

    // Cập nhật user
    await this.userAuthRepository.updateTwoFactorSettings(userId, {
      twoFactorEnabled: false,
      twoFactorSecret: null,
      twoFactorMethod: null,
      twoFactorVerifiedAt: null
    })

    // Xóa tất cả mã khôi phục
    await this.recoveryCodeRepository.deleteAllUserRecoveryCodes(userId)

    return {
      message: await this.i18nService.t('auth.Auth.2FA.Disable.Success')
    }
  }

  /**
   * Tạo lại mã khôi phục
   */
  async regenerateRecoveryCodes(
    userId: number,
    totpCode: string,
    ip?: string,
    userAgent?: string
  ): Promise<{ message: string; recoveryCodes: string[] }> {
    // Tìm user
    const user = await this.userAuthRepository.findById(userId)

    if (!user) {
      throw AuthError.EmailNotFound()
    }

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      throw AuthError.TOTPNotEnabled()
    }

    // Xác minh TOTP
    const isValid = this.verifyTOTP(user.twoFactorSecret, totpCode)

    if (!isValid) {
      throw AuthError.InvalidTOTP()
    }

    // Xóa tất cả mã khôi phục cũ
    await this.recoveryCodeRepository.deleteAllUserRecoveryCodes(userId)

    // Tạo mã khôi phục mới
    const recoveryCodes = this.generateRecoveryCodes()
    const hashedRecoveryCodes = await Promise.all(
      recoveryCodes.map(async (code) => await this.hashingService.hash(code))
    )

    // Lưu mã khôi phục mới
    await this.recoveryCodeRepository.createRecoveryCodes(userId, hashedRecoveryCodes)

    return {
      message: await this.i18nService.t('auth.Auth.2FA.RecoveryCodesRegenerated'),
      recoveryCodes
    }
  }

  private getTrustExpirationDate(): Date {
    const trustDurationDays = this.configService.get<number>('security.deviceTrustDurationDays', 30)
    const expirationDate = new Date()
    expirationDate.setDate(expirationDate.getDate() + trustDurationDays)
    return expirationDate
  }

  async initiateTwoFactorActionWithSltCookie(payload: {
    userId: number
    deviceId: number
    ipAddress: string
    userAgent: string
    purpose: TypeOfVerificationCode
    metadata?: Record<string, any>
  }): Promise<string> {
    const { userId, deviceId, ipAddress, userAgent, purpose, metadata } = payload
    this.logger.debug(
      `[TwoFactorService] Initiating 2FA action SLT for user ${userId}, device ${deviceId}, purpose ${purpose}`
    )

    const sltTokenId = `slt_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`
    const sltTokenLifetime = this.configService.get<number>('jwt.sltTokenLifetime', 300) // 5 minutes in seconds

    const sltJwtPayload = {
      jti: sltTokenId,
      sub: userId,
      pur: purpose
    }

    const sltToken = this.jwtService.sign(sltJwtPayload, {
      secret: this.configService.get<string>('jwt.sltSecret'),
      expiresIn: sltTokenLifetime
    })

    const sltContextKey = RedisKeyManager.sltContextKey(sltTokenId)
    const sltContextData = {
      userId: userId.toString(),
      deviceId: deviceId.toString(),
      ipAddress,
      userAgent,
      purpose,
      sltJwtExp: (Math.floor(Date.now() / 1000) + sltTokenLifetime).toString(),
      sltJwtCreatedAt: Math.floor(Date.now() / 1000).toString(),
      finalized: '0', // Not finalized yet
      attempts: '0',
      ...(metadata && { metadata: JSON.stringify(metadata) })
    }

    await this.redisService.hset(sltContextKey, sltContextData)
    await this.redisService.expire(sltContextKey, sltTokenLifetime)

    this.logger.debug(
      `[TwoFactorService] SLT context for 2FA action saved to Redis with key ${sltContextKey} and TTL ${sltTokenLifetime}s`
    )
    return sltToken
  }
}
