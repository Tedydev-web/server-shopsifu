import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { JwtService } from '@nestjs/jwt'
import * as speakeasy from 'speakeasy'
import * as QRCode from 'qrcode'
import { Response } from 'express'
import { I18nService } from 'nestjs-i18n'
import { OtpService } from '../otp/otp.service'
import { HashingService } from 'src/shared/services/hashing.service'
import { TypeOfVerificationCode, TwoFactorMethodType } from 'src/routes/auth/constants/auth.constants'
import { CookieService } from 'src/routes/auth/shared/cookie/cookie.service'
import { TokenService } from 'src/routes/auth/shared/token/token.service'
import { UserAuthRepository } from '../../repositories/user-auth.repository'
import { RecoveryCodeRepository } from '../../repositories/recovery-code.repository'
import { DeviceRepository } from '../../repositories/device.repository'
import { AuthError } from 'src/routes/auth/auth.error'

@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name)

  constructor(
    private readonly configService: ConfigService,
    private readonly i18nService: I18nService,
    private readonly cookieService: CookieService,
    private readonly tokenService: TokenService,
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
    // Tìm user
    const user = await this.userAuthRepository.findById(userId)

    if (!user) {
      throw AuthError.EmailNotFound()
    }

    // Kiểm tra 2FA đã được kích hoạt chưa
    if (user.twoFactorEnabled) {
      throw AuthError.TOTPAlreadyEnabled()
    }

    // Tạo secret cho TOTP
    const { secret, otpauthUrl } = this.createTOTP(user.email)

    // Tạo QR code
    const qrCodeUri = await QRCode.toDataURL(otpauthUrl)

    // Tạo SLT cho bước xác nhận thiết lập
    const sltJwt = await this.otpService.initiateOtpWithSltCookie({
      email: user.email,
      userId: user.id,
      deviceId,
      ipAddress: ip,
      userAgent,
      purpose: TypeOfVerificationCode.SETUP_2FA,
      metadata: {
        secret,
        twoFactorMethod: TwoFactorMethodType.TOTP
      }
    })

    // Set SLT cookie
    this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.SETUP_2FA)

    return {
      secret,
      uri: qrCodeUri
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
    res: Response
  ): Promise<{ message: string }> {
    // Xác minh SLT và lấy context
    const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
      sltCookieValue,
      ip,
      userAgent,
      TypeOfVerificationCode.LOGIN_2FA
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
    let methodUsed = user.twoFactorMethod || TwoFactorMethodType.TOTP

    // Kiểm tra phương thức xác thực
    if (user.twoFactorMethod === TwoFactorMethodType.TOTP) {
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
    } else {
      // Xác minh recovery code
      const recoveryCodeVerified = await this.verifyRecoveryCode(user.id, code)
      if (recoveryCodeVerified) {
        isVerified = true
        methodUsed = TwoFactorMethodType.RECOVERY
      }
    }

    if (!isVerified) {
      throw AuthError.InvalidTOTP()
    }

    // Tìm hoặc tạo device
    const device = await this.deviceRepository.upsertDevice(user.id, userAgent, ip)

    // Nếu là mã khôi phục, đánh dấu là đã sử dụng
    if (methodUsed === TwoFactorMethodType.RECOVERY) {
      // Không cần làm gì thêm vì đã được đánh dấu trong hàm verifyRecoveryCode
    }

    // Tạo phiên đăng nhập và trả về tokens
    // TODO: Implement với CoreService hoặc SessionService

    // Xóa SLT cookie
    this.cookieService.clearSltCookie(res)

    return {
      message: await this.i18nService.translate('Auth.2FA.VerifySuccess')
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
