// NestJS core modules
import { Injectable, Logger, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'

// External libraries
import * as otplib from 'otplib'
import { HashAlgorithms } from '@otplib/core'

// Internal services
import { HashingService } from 'src/shared/services/hashing.service'
import { SLTService } from 'src/shared/services/slt.service'
import { EmailService } from 'src/shared/services/email.service'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { UserAgentService } from 'src/shared/services/user-agent.service'

// Repositories
import { UserRepository } from 'src/routes/user/user.repository'
import { RecoveryCodeRepository } from 'src/routes/auth/repositories'

// Types and interfaces
import { IMultiFactorService } from 'src/routes/auth/auth.types'

// Constants and enums
import { TypeOfVerificationCode, TwoFactorMethodType } from 'src/routes/auth/auth.constants'

// Errors and injection tokens
import { AuthError } from '../auth.error'
import { GlobalError } from 'src/shared/global.error'
import {
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  HASHING_SERVICE,
  SLT_SERVICE,
  USER_AGENT_SERVICE
} from 'src/shared/constants/injection.tokens'
import { I18nContext } from 'nestjs-i18n'

const RECOVERY_CODES_COUNT = 8
const RECOVERY_CODE_LENGTH = 10
const TOTP_WINDOW = 2 // Cho phép mã hợp lệ trong khoảng thời gian 60 giây trước/sau

interface TotpSetupResult {
  secret: string
  uri: string
}

@Injectable()
export class TwoFactorService implements IMultiFactorService {
  private readonly logger = new Logger(TwoFactorService.name)
  private readonly authenticator: typeof otplib.authenticator

  constructor(
    private readonly configService: ConfigService,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    private readonly userRepository: UserRepository,
    private readonly recoveryCodeRepository: RecoveryCodeRepository,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService
  ) {
    // Cấu hình authenticator
    this.authenticator = otplib.authenticator
    this.authenticator.options = {
      window: TOTP_WINDOW,
      step: 30, // 30 giây cho mỗi mã
      digits: 6,
      algorithm: HashAlgorithms.SHA1
    }
  }

  async generateSetupDetails(userId: number): Promise<{ message: string; data: { secret: string; qrCode: string } }> {
    const user = await this.userRepository.findById(userId)

    if (!user) {
      throw GlobalError.NotFound('user')
    }

    if (user.twoFactorEnabled) {
      throw AuthError.TOTPAlreadyEnabled()
    }

    const { secret, uri } = this.createTOTP(user.email)
    const qrCode = await this.generateQRCode(uri)

    return {
      message: 'auth.success.2fa.setupInitiated',
      data: {
        secret,
        qrCode
      }
    }
  }

  async generateVerificationCode(options?: { secret: string }): Promise<string> {
    if (!options || !options.secret) {
      throw AuthError.InvalidTOTP()
    }

    return Promise.resolve(this.authenticator.generate(options.secret))
  }

  async verifyCode(
    code: string,
    context: {
      userId: number
      method?: string
      secret?: string
    }
  ): Promise<boolean> {
    // Xác định phương thức xác minh sẽ sử dụng
    const verificationMethod = context.method ?? TwoFactorMethodType.TOTP

    // Nếu context cung cấp secret trực tiếp và method là TOTP (trong quá trình thiết lập),
    // sử dụng secret đó trực tiếp.
    if (context.secret && verificationMethod === 'TOTP') {
      if (this.verifyTOTP(context.secret, code)) {
        return true
      }
      throw AuthError.InvalidTOTP()
    }

    // Xử lý dựa trên phương thức
    switch (verificationMethod as TwoFactorMethodType) {
      case TwoFactorMethodType.TOTP: {
        const user = await this.userRepository.findById(context.userId)
        if (!user?.twoFactorEnabled || !user.twoFactorSecret) {
          throw AuthError.TOTPNotEnabled()
        }
        // Thử xác minh bằng TOTP trước
        if (this.verifyTOTP(user.twoFactorSecret, code)) {
          return true
        }
        // Nếu TOTP thất bại, thử mã khôi phục như một phương án dự phòng
        const isRecoveryCode = await this.verifyRecoveryCode(context.userId, code)
        if (isRecoveryCode) {
          return true
        }
        // Nếu cả hai đều thất bại
        throw AuthError.InvalidTOTP()
      }

      case TwoFactorMethodType.RECOVERY_CODE: {
        // Kiểm tra user tồn tại và 2FA đã được enable
        const user = await this.userRepository.findById(context.userId)
        if (!user) {
          throw GlobalError.NotFound('user')
        }
        if (!user.twoFactorEnabled) {
          throw AuthError.TOTPNotEnabled()
        }

        const isVerified = await this.verifyRecoveryCode(context.userId, code)
        if (!isVerified) {
          throw AuthError.InvalidRecoveryCode()
        }

        return true
      }

      default:
        throw AuthError.InvalidVerificationMethod()
    }
  }

  async disableVerification(userId: number, code: string, method?: string): Promise<{ message: string }> {
    // 1. Verify user with the provided code
    await this.verifyCode(code, { userId, method })

    // 2. Perform the actual disabling logic
    await this._performDisable(userId)

    // 3. Return success message
    return {
      message: 'auth.success.2fa.disabled'
    }
  }

  async disableVerificationAfterConfirm(userId: number): Promise<{ message: string }> {
    await this._performDisable(userId)
    return {
      message: 'auth.success.2fa.disabled'
    }
  }

  private async _performDisable(userId: number): Promise<void> {
    // 1. Get user information
    const user = await this.userRepository.findByIdWithDetails(userId)
    if (!user) throw GlobalError.NotFound('user')

    // 2. Disable 2FA and delete recovery codes
    await this.userRepository.disableTwoFactor(userId)

    await this.recoveryCodeRepository.deleteRecoveryCodes(userId)

    // 4. Send notification email
    await this.emailService.sendTwoFactorStatusChangedEmail(user.email, {
      userName: user.userProfile?.username ?? user.email,
      action: 'disabled',
      details: []
    })
  }

  async regenerateRecoveryCodes(
    userId: number,
    code: string,
    method?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ message: string; data: { recoveryCodes: string[] } }> {
    // 1. Check user exists and 2FA is enabled FIRST
    const user = await this.userRepository.findByIdWithDetails(userId)

    // 2. Then verify the provided code
    await this.verifyCode(code, { userId, method })

    const plainRecoveryCodes = this.generateRecoveryCodes()

    const hashedRecoveryCodes = await Promise.all(plainRecoveryCodes.map((code) => this.hashingService.hash(code)))

    await this.recoveryCodeRepository.tx(async (tx) => {
      await this.recoveryCodeRepository.deleteRecoveryCodes(userId, tx)
      await this.recoveryCodeRepository.createRecoveryCodes(userId, hashedRecoveryCodes, tx)
    })

    const i18nLang = I18nContext.current()?.lang
    const lang = i18nLang === 'en' ? 'en' : 'vi'
    const details = []
    if (ipAddress && userAgent) {
      const locationResult = await this.geolocationService.getLocationFromIP(ipAddress)
      const uaInfo = this.userAgentService.parse(userAgent)
      const localeForDate = lang === 'vi' ? 'vi-VN' : 'en-US'

      details.push(
        {
          label: 'email.Email.common.details.time',
          value: new Date().toLocaleString(localeForDate, {
            timeZone: locationResult.timezone || 'Asia/Ho_Chi_Minh',
            dateStyle: 'full',
            timeStyle: 'long'
          })
        },
        {
          label: 'email.Email.common.details.ipAddress',
          value: ipAddress
        },
        {
          label: 'email.Email.common.details.device',
          value: `${uaInfo.browser} on ${uaInfo.os}`
        }
      )
    }

    await this.emailService.sendRecoveryCodesEmail(user.email, {
      userName: user.userProfile?.username ?? user.email,
      recoveryCodes: plainRecoveryCodes,
      details,
      lang
    })

    return {
      message: 'auth.success.2fa.recoveryCodesRegenerated',
      data: { recoveryCodes: plainRecoveryCodes }
    }
  }

  async verifyByMethod(
    method: string,
    code: string,
    userId: number
  ): Promise<{ message: string; data: { success: boolean; method: string } }> {
    // Lấy thông tin người dùng
    const user = await this.userRepository.findById(userId)

    if (!user) {
      throw GlobalError.NotFound('user')
    }

    // Kiểm tra trạng thái 2FA trước khi verify bất kỳ method nào
    if (!user.twoFactorEnabled) {
      throw AuthError.TOTPNotEnabled()
    }

    // Xác minh theo phương thức cụ thể
    let success = false

    if (method === 'TOTP' && user.twoFactorSecret) {
      success = this.verifyTOTP(user.twoFactorSecret, code)
    } else if (method === 'RECOVERY') {
      success = await this.verifyRecoveryCode(userId, code)
    } else {
      throw AuthError.InvalidVerificationMethod()
    }

    if (success) {
      return {
        message: 'auth.success.otp.verified',
        data: { success, method }
      }
    }

    // Nếu không thành công, throw lỗi thay vì trả về success: false
    throw AuthError.InvalidOTP()
  }

  private createTOTP(email: string, secret?: string): TotpSetupResult {
    // Tạo secret nếu chưa được cung cấp
    const finalSecret = secret || this.authenticator.generateSecret()

    // Tạo URI cho TOTP
    const uri = this.authenticator.keyuri(email, 'Shopsifu', finalSecret)

    return {
      secret: finalSecret,
      uri
    }
  }

  async confirmTwoFactorSetup(
    userId: number,
    totpCode: string,
    secret: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ message: string; data: { recoveryCodes: string[] } }> {
    const user = await this.userRepository.findByIdWithDetails(userId)
    if (!user) throw GlobalError.NotFound('user')

    if (!this.verifyTOTP(secret, totpCode)) throw AuthError.InvalidTOTP()

    await this.userRepository.enableTwoFactor(userId, secret, TwoFactorMethodType.TOTP)

    // This call now also sends an email with the codes
    const result = await this.regenerateRecoveryCodes(
      userId,
      totpCode, // Dùng lại totpCode để xác thực vì nó vẫn hợp lệ
      TwoFactorMethodType.TOTP,
      ipAddress,
      userAgent
    )

    await this.emailService.sendTwoFactorStatusChangedEmail(user.email, {
      userName: user.userProfile?.username ?? user.email,
      action: 'enabled',
      details: []
    })

    return {
      message: 'auth.success.2fa.setupConfirmed',
      data: { recoveryCodes: result.data.recoveryCodes }
    }
  }

  private generateRecoveryCodes(count: number = RECOVERY_CODES_COUNT): string[] {
    const codes: string[] = []
    for (let i = 0; i < count; i++) {
      codes.push(this.generateRandomString(RECOVERY_CODE_LENGTH))
    }
    return codes
  }

  private generateRandomString(length: number): string {
    // Không sử dụng ký tự dễ gây nhầm lẫn
    const characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    let result = ''
    const charactersLength = characters.length

    // Thêm dấu gạch ngang sau mỗi 5 ký tự
    for (let i = 0; i < length; i++) {
      if (i > 0 && i % 5 === 0) {
        result += '-'
      }
      result += characters.charAt(Math.floor(Math.random() * charactersLength))
    }

    return result
  }

  private verifyTOTP(secret: string, token: string): boolean {
    try {
      const isValid = this.authenticator.verify({ token, secret })
      return isValid
    } catch (error) {
      return false
    }
  }

  private async verifyRecoveryCode(userId: number, code: string): Promise<boolean> {
    // Normalize input code - ensure uppercase and proper format
    const normalizedCode = code.toUpperCase().trim()

    const recoveryCodes = await this.recoveryCodeRepository.findByUserId(userId)

    if (!recoveryCodes.length) {
      return false
    }

    for (const storedCode of recoveryCodes) {
      if (storedCode.used) {
        continue
      }

      const codeMatches = await this.hashingService.compare(normalizedCode, storedCode.code)

      if (codeMatches) {
        await this.recoveryCodeRepository.markRecoveryCodeAsUsed(storedCode.id)
        return true
      }
    }

    return false
  }

  async initiateTwoFactorActionWithSltCookie(payload: {
    userId: number
    deviceId: number
    ipAddress: string
    userAgent: string
    purpose: TypeOfVerificationCode
    metadata?: Record<string, any>
  }): Promise<string> {
    return this.sltService.createAndStoreSltToken(payload)
  }

  private getTrustExpirationDate(): Date {
    const trustDurationDays = this.configService.get<number>('security.deviceTrustDurationDays', 30)
    const expirationDate = new Date()
    expirationDate.setDate(expirationDate.getDate() + trustDurationDays)
    return expirationDate
  }

  private async generateQRCode(uri: string): Promise<string> {
    const QRCode = await import('qrcode')
    return QRCode.toDataURL(uri)
  }
}
