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
import { v4 as uuidv4 } from 'uuid'

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
    this.logger.debug(`Setting up 2FA for user ${userId} from device ${deviceId}`)

    // Tìm user
    const user = await this.userAuthRepository.findById(userId)

    if (!user) {
      this.logger.error(`User with ID ${userId} not found when setting up 2FA`)
      throw AuthError.EmailNotFound()
    }

    // Kiểm tra 2FA đã được kích hoạt chưa
    if (user.twoFactorEnabled) {
      this.logger.warn(`User ${userId} already has 2FA enabled`)
      throw AuthError.TOTPAlreadyEnabled()
    }

    try {
      // Tạo secret cho TOTP
      const { secret, otpauthUrl } = this.createTOTP(user.email)
      this.logger.debug(`TOTP secret generated for user ${userId}`)

      // Tạo QR code
      const qrCodeUri = await QRCode.toDataURL(otpauthUrl)
      this.logger.debug(`QR code URI generated, length: ${qrCodeUri.length}`)

      // Tạo JWT token (không gửi OTP email)
      const sltJwtPayload = {
        jti: `slt_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`,
        sub: user.id,
        pur: TypeOfVerificationCode.SETUP_2FA
      }

      const sltJwt = this.tokenService.signShortLivedToken(sltJwtPayload)

      // Lưu context vào Redis
      const contextKey = `slt:context:${sltJwtPayload.jti}`
      const contextData = {
        userId: user.id,
        deviceId: deviceId,
        ipAddress: ip,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.SETUP_2FA,
        sltJwtExp: Math.floor(Date.now() / 1000) + 300, // 5 phút
        sltJwtCreatedAt: Date.now(),
        finalized: '0',
        attempts: 0,
        metadata: {
          secret,
          twoFactorMethod: TwoFactorMethodType.TOTP
        },
        email: user.email
      }

      await this.otpService['redisService'].set(contextKey, JSON.stringify(contextData), 'EX', 360) // 6 phút

      // Set SLT cookie
      this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.SETUP_2FA)
      this.logger.debug(`SLT cookie set for user ${userId} for 2FA setup confirmation (no email OTP sent)`)

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
    res: Response
  ): Promise<{
    message: string
    requiresDeviceVerification?: boolean
    user?: {
      id: number
      email: string
      roleName: string
      isDeviceTrustedInSession: boolean
      userProfile: any
    }
  }> {
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

    // Lấy thông tin về thiết bị từ context
    const requiresDeviceVerification = sltContext.metadata?.requiresDeviceVerification === true
    const rememberedMe = sltContext.metadata?.rememberMe === true

    this.logger.debug(`2FA verification successful for user ${user.id}, device trust status: ${device.isTrusted}`)
    this.logger.debug(`requiresDeviceVerification: ${requiresDeviceVerification}`)

    // Nếu sau khi xác minh 2FA thành công, thiết bị vẫn chưa tin cậy
    if (requiresDeviceVerification) {
      this.logger.debug(`Device verification required after successful 2FA for user ${user.id}`)

      // Xóa SLT cookie cũ
      this.cookieService.clearSltCookie(res)

      // Khởi tạo OTP cho thiết bị mới
      const deviceSltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: user.email,
        userId: user.id,
        deviceId: device.id,
        ipAddress: ip,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
        metadata: {
          deviceId: device.id,
          rememberMe: rememberedMe,
          twoFactorVerified: true // Đánh dấu đã xác minh 2FA
        }
      })

      // Đặt cookie SLT mới
      this.cookieService.setSltCookie(res, deviceSltJwt, TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP)
      this.logger.debug(`Device verification OTP initiated after 2FA for user ${user.id}`)

      return {
        message: await this.i18nService.translate('auth.Auth.Login.DeviceVerificationRequired'),
        requiresDeviceVerification: true
      }
    }

    // Nếu không cần xác minh thiết bị nữa, hoàn tất đăng nhập
    // Tạo phiên đăng nhập và trả về tokens
    const sessionId = uuidv4()

    // Tạo payload cho access token
    const tokenPayload = {
      userId: user.id,
      deviceId: device.id,
      roleId: user.roleId,
      roleName: user.role.name,
      sessionId,
      jti: `access_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`,
      isDeviceTrustedInSession: device.isTrusted
    }

    // Tạo tokens
    const accessToken = this.tokenService.signAccessToken(tokenPayload)
    const refreshToken = this.tokenService.signRefreshToken({
      ...tokenPayload,
      jti: `refresh_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`
    })

    // Set cookie
    this.cookieService.setTokenCookies(
      res,
      accessToken,
      refreshToken,
      rememberedMe ? 30 * 24 * 60 * 60 * 1000 : undefined
    )

    // Xóa SLT cookie
    this.cookieService.clearSltCookie(res)

    return {
      message: await this.i18nService.translate('Auth.2FA.Verify.Success'),
      requiresDeviceVerification: false,
      user: {
        id: user.id,
        email: user.email,
        roleName: user.role.name,
        isDeviceTrustedInSession: device.isTrusted,
        userProfile: {
          firstName: user.userProfile?.firstName,
          lastName: user.userProfile?.lastName,
          username: user.userProfile?.username,
          avatar: user.userProfile?.avatar
        }
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
