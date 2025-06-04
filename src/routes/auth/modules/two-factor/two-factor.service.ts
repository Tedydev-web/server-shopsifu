import { Injectable, Logger, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import * as speakeasy from 'speakeasy'
import * as QRCode from 'qrcode'
import { Response } from 'express'
import { I18nService } from 'nestjs-i18n'
import { OtpService } from '../otp/otp.service'
import { HashingService } from 'src/shared/services/hashing.service'
import { TypeOfVerificationCode, TwoFactorMethodType } from 'src/shared/constants/auth.constants'
import { ICookieService, ITokenService } from 'src/shared/types/auth.types'
import { COOKIE_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { AuthError } from 'src/routes/auth/auth.error'
import { v4 as uuidv4 } from 'uuid'
import { TwoFactorConfirmSetupDto } from './dto/two-factor.dto'
import { UserAuthRepository, RecoveryCodeRepository, DeviceRepository } from 'src/shared/repositories/auth'

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
    private readonly deviceRepository: DeviceRepository
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
      const contextKey = `slt:context:${sltJwtPayload.jti}`
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

      await this.otpService['redisService'].hset(contextKey, contextData as any)
      await this.otpService['redisService'].expire(contextKey, 360) // 6 phút

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
      message: await this.i18nService.translate('Auth.2FA.SetupSuccess'),
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
    res: Response,
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
      userProfile: any
    }
    // Các trường bổ sung để xử lý các purpose khác
    purpose?: string
    userId?: number
    metadata?: any
  }> {
    // Xác thực SLT token và lấy context
    const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
      sltCookieValue,
      ip,
      userAgent
      // Loại bỏ TypeOfVerificationCode.LOGIN_2FA để có thể sử dụng cho nhiều purpose
    )

    if (!sltContext.userId) {
      throw AuthError.EmailNotFound()
    }

    // Tìm user
    const user = await this.userAuthRepository.findById(sltContext.userId)

    if (!user) {
      throw AuthError.EmailNotFound()
    }

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      throw AuthError.TOTPNotEnabled()
    }

    let isVerified = false
    let methodUsed =
      method === 'RECOVERY_CODE' ? TwoFactorMethodType.RECOVERY : user.twoFactorMethod || TwoFactorMethodType.TOTP

    // Kiểm tra phương thức xác thực
    if (method === 'RECOVERY_CODE') {
      // Xác minh recovery code
      const recoveryCodeVerified = await this.verifyRecoveryCode(user.id, code)
      if (recoveryCodeVerified) {
        isVerified = true
        methodUsed = TwoFactorMethodType.RECOVERY
      }
    } else if (user.twoFactorMethod === TwoFactorMethodType.TOTP) {
      // Xác minh TOTP
      isVerified = this.verifyTOTP(user.twoFactorSecret, code)
    } else if (user.twoFactorMethod === TwoFactorMethodType.OTP) {
      // Xác minh OTP
      try {
        await this.otpService.verifyOTP(user.email, code, TypeOfVerificationCode.LOGIN_2FA)
        isVerified = true
      } catch (error) {
        isVerified = false
      }
    }

    if (!isVerified) {
      throw AuthError.InvalidTOTP()
    }

    // Đánh dấu SLT là đã finalized
    await this.otpService.finalizeSlt(sltContext.sltJti)

    // Kiểm tra purpose trong context
    if (
      sltContext.purpose === TypeOfVerificationCode.REVOKE_SESSIONS ||
      sltContext.purpose === TypeOfVerificationCode.REVOKE_ALL_SESSIONS
    ) {
      // Trả về thông tin cần thiết để controller xử lý tiếp
      return {
        message: await this.i18nService.translate('Auth.2FA.Verify.Success'),
        verifiedMethod: methodUsed,
        purpose: sltContext.purpose,
        userId: sltContext.userId,
        metadata: sltContext.metadata
      }
    }

    // Tìm hoặc tạo device
    const device = await this.deviceRepository.upsertDevice(user.id, userAgent, ip)

    // Lấy thông tin thiết bị có tin cậy không
    const isDeviceTrusted = device.isTrusted && (await this.deviceRepository.isDeviceTrustValid(device.id))
    this.logger.debug(`2FA verification successful for user ${user.id}, device trust status: ${isDeviceTrusted}`)

    // Xóa SLT cookie của 2FA chỉ khi purpose không phải là REVOKE_SESSIONS hoặc REVOKE_ALL_SESSIONS
    this.cookieService.clearSltCookie(res)

    // Xác định xem 2FA đã xong và chúng ta có thể đăng nhập ngay sau khi verify 2FA
    // Luôn hoàn tất đăng nhập sau khi xác thực 2FA thành công, không cần thêm xác minh thiết bị
    const finalizeAfter2FA = true

    if (finalizeAfter2FA) {
      // Thiết bị đã được tin cậy nên hoàn tất đăng nhập sau 2FA
      // Hoặc đã xác thực qua TOTP/Recovery code nên ko cần thêm xác minh thiết bị
      const payload = {
        userId: user.id,
        deviceId: device.id,
        roleId: user.roleId,
        roleName: user.role.name,
        sessionId: uuidv4(),
        jti: `access_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`,
        isDeviceTrustedInSession: isDeviceTrusted
      }

      // Tạo token
      const accessToken = this.tokenService.signAccessToken(payload)
      const refreshToken = this.tokenService.signRefreshToken({
        ...payload,
        jti: `refresh_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`
      })

      // Set token cookies
      this.cookieService.setTokenCookies(
        res,
        accessToken,
        refreshToken,
        sltContext.metadata?.rememberMe ? 30 * 24 * 60 * 60 * 1000 : undefined
      )

      // Trả về thông tin user đã đăng nhập
      return {
        message: await this.i18nService.translate('Auth.2FA.Verify.Success'),
        verifiedMethod: methodUsed,
        user: {
          id: user.id,
          email: user.email,
          roleName: user.role.name,
          isDeviceTrustedInSession: isDeviceTrusted,
          userProfile: {
            firstName: user.userProfile?.firstName,
            lastName: user.userProfile?.lastName,
            username: user.userProfile?.username,
            avatar: user.userProfile?.avatar
          }
        }
      }
    } else {
      // Tuy nhiên code branch này không bao giờ được thực thi do finalizeAfter2FA = true
      // Giữ lại chỉ để tham khảo cho tương lai nếu cần
      this.logger.debug(`Device verification required after successful 2FA for user ${user.id}`)

      // Khởi tạo OTP cho verifications thiết bị sau khi 2FA thành công
      const sltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: user.email,
        userId: user.id,
        deviceId: device.id,
        ipAddress: ip,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
        metadata: {
          deviceId: device.id,
          rememberMe: sltContext.metadata?.rememberMe,
          twoFactorVerified: true // Đánh dấu đã xác minh 2FA
        }
      })

      // Đặt cookie SLT
      this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP)

      return {
        message: await this.i18nService.translate('Auth.2FA.Verify.AskToTrustDevice'),
        requiresDeviceVerification: true,
        verifiedMethod: methodUsed
      }
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
      message: await this.i18nService.translate('Auth.2FA.DisableSuccess')
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
      message: await this.i18nService.translate('Auth.2FA.RecoveryCodesRegenerated'),
      recoveryCodes
    }
  }
}
