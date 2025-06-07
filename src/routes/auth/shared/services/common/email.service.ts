import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'
import { I18nContext } from 'nestjs-i18n'
import { Resend } from 'resend'
import * as React from 'react'
import { render } from '@react-email/render'
import { TypeOfVerificationCodeType } from 'src/routes/auth/shared/constants/auth.constants'
import I18nEmail from 'src/i18n/vi/email.json'
import OtpEmail from 'emails/otp-email'
import SecurityAlertEmail from 'emails/security-alert-email'

// Định nghĩa type cho hàm translate
type TranslateFunction = (key: string, options?: Record<string, any>) => string

// Các loại cảnh báo bảo mật
export enum SecurityAlertType {
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  LOGIN_FROM_NEW_DEVICE = 'LOGIN_FROM_NEW_DEVICE',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  TWO_FACTOR_ENABLED = 'TWO_FACTOR_ENABLED',
  TWO_FACTOR_DISABLED = 'TWO_FACTOR_DISABLED',
  EMAIL_CHANGED = 'EMAIL_CHANGED',
  DEVICE_TRUSTED = 'DEVICE_TRUSTED',
  DEVICE_UNTRUSTED = 'DEVICE_UNTRUSTED',
  ACCOUNT_LINKED = 'ACCOUNT_LINKED',
  ACCOUNT_UNLINKED = 'ACCOUNT_UNLINKED',
  SESSIONS_REVOKED = 'SESSIONS_REVOKED',
  DEVICE_LIMIT_WARNING = 'DEVICE_LIMIT_WARNING',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY'
}

// Payload cho email cảnh báo bảo mật
export interface SecurityAlertEmailPayload {
  to: string
  userName?: string
  alertSubject: string
  alertTitle: string
  mainMessage: string
  actionDetails?: Array<{ label: string; value: string }>
  actionButtonText?: string
  actionButtonUrl?: string
  secondaryMessage?: string
  lang?: 'vi' | 'en'
}

// Payload cho email OTP
export interface OtpEmailPayload {
  email: string
  otpCode: string
  otpType: TypeOfVerificationCodeType
  lang?: 'vi' | 'en'
}

/**
 * Dịch vụ gửi email
 */
@Injectable()
export class EmailService {
  private resend: Resend | undefined // Đặt undefined để kiểm tra sự tồn tại
  private readonly logger = new Logger(EmailService.name)
  private readonly isProduction: boolean
  private readonly notificationEmailFrom: string
  private readonly securityEmailFrom: string
  private readonly frontendUrl: string

  constructor(
    private readonly configService: ConfigService,
    private readonly i18nService: I18nService
  ) {
    // Khởi tạo Resend API client
    const resendApiKey = this.configService.get<string>('RESEND_API_KEY')
    if (!resendApiKey) {
      this.logger.warn('RESEND_API_KEY chưa được cấu hình. Email sẽ không được gửi.')
    } else {
      this.resend = new Resend(resendApiKey)
      this.logger.log('Resend API client đã khởi tạo thành công.')
    }

    // Cấu hình khác
    this.isProduction = ['production', 'staging'].includes(this.configService.get<string>('NODE_ENV') ?? 'development')
    this.notificationEmailFrom =
      this.configService.get<string>('NOTI_MAIL_FROM_ADDRESS') ?? 'Shopsifu <no-reply@shopsifu.live>'
    this.securityEmailFrom =
      this.configService.get<string>('SEC_MAIL_FROM_ADDRESS') ?? 'Shopsifu Security <security@shopsifu.live>'
    this.frontendUrl = this.configService.get<string>('FRONTEND_URL') ?? 'https://localhost:8000'

    this.logger.debug(
      `EmailService khởi tạo với cấu hình: isProduction=${this.isProduction}, notificationEmailFrom=${this.notificationEmailFrom}, securityEmailFrom=${this.securityEmailFrom}, frontendUrl=${this.frontendUrl}`
    )
  }

  /**
   * Gửi email OTP
   */
  async sendOtpEmail(payload: OtpEmailPayload): Promise<void> {
    const { email, otpCode, otpType } = payload
    this.logger.debug(`Chuẩn bị gửi email OTP cho ${email}, loại: ${otpType}`)

    try {
      // Xác định ngôn ngữ, mặc định là 'vi'
      const lang = (payload.lang ?? I18nContext.current()?.lang === 'en') ? 'en' : 'vi'

      // Render component React thành HTML
      const emailHtml = await render(React.createElement(OtpEmail, { otpCode, otpType, lang }))

      // Lấy chủ đề email từ cấu trúc i18n
      const subject = I18nEmail.Email.otp[otpType]?.subject ?? I18nEmail.Email.otp.default.subject

      if (!this.resend) {
        this.logger.warn(`Resend API chưa được cấu hình. Email OTP không được gửi đến ${email}`)
        return
      }

      await this.resend.emails.send({
        from: this.notificationEmailFrom,
        to: email,
        subject,
        html: emailHtml
      })

      this.logger.log(`Email OTP ${otpCode} đã được gửi đến ${email} cho mục đích ${otpType}`)
    } catch (error) {
      this.logger.error(`Không thể gửi email OTP: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Gửi email thông báo bảo mật
   */
  async sendSecurityAlertEmail(
    alertType: SecurityAlertType,
    email: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    try {
      // Chuẩn bị nội dung email
      const alertContent = this.prepareSecurityAlertContent(alertType, email, metadata)

      // Render email với React
      let emailHtml: string
      try {
        emailHtml = await render(React.createElement(SecurityAlertEmail, alertContent))
      } catch (renderError) {
        this.logger.error(`Lỗi khi render email Security Alert: ${renderError.message}`, renderError.stack)
        throw new Error(`Không thể render email template: ${renderError.message}`)
      }

      // Kiểm tra Resend trước khi gửi
      if (!this.resend) {
        this.logger.warn(`Resend API chưa được cấu hình. Email không được gửi (alertType: ${alertType}, to: ${email})`)
        return
      }

      const result = await this.resend.emails.send({
        from: this.securityEmailFrom,
        to: [email],
        subject: alertContent.alertSubject,
        html: emailHtml
      })

      this.logger.debug(`Email cảnh báo bảo mật gửi thành công: ${JSON.stringify(result)}`)
      this.logger.log(`Đã gửi email thông báo bảo mật ${alertType} đến ${email}`, metadata)
    } catch (error) {
      this.logger.error(`Lỗi khi gửi email thông báo bảo mật: ${error.message}`, error.stack)
      // Không throw lỗi để không làm gián đoạn luồng bảo mật
    }
  }

  /**
   * Chuẩn bị nội dung email cảnh báo bảo mật
   */
  private prepareSecurityAlertContent(
    alertType: SecurityAlertType,
    email: string,
    metadata?: Record<string, any>
  ): SecurityAlertEmailPayload {
    const currentLang = I18nContext.current()?.lang
    const lang = currentLang === 'en' ? 'en' : 'vi'
    const userName = metadata?.userName

    // Định nghĩa hàm t với type rõ ràng
    const t: TranslateFunction = (key, options) => this.i18nService.t(key, { lang, ...options })

    let alertSubject: string
    let alertTitle: string
    let mainMessage: string
    let secondaryMessage: string | undefined
    let actionButtonText: string | undefined
    let actionButtonUrl: string | undefined
    let actionDetails: Array<{ label: string; value: string }> | undefined

    // Lấy các nội dung đã được dịch
    switch (alertType) {
      case SecurityAlertType.PASSWORD_CHANGED:
        alertSubject = t('email.Email.securityAlert.PASSWORD_CHANGED.subject')
        alertTitle = t('email.Email.securityAlert.PASSWORD_CHANGED.title')
        mainMessage = t('email.Email.securityAlert.PASSWORD_CHANGED.mainMessage')
        secondaryMessage = t('email.Email.securityAlert.PASSWORD_CHANGED.secondaryMessage')
        actionButtonText = t('email.Email.securityAlert.PASSWORD_CHANGED.buttonText')
        actionButtonUrl = `${this.frontendUrl}/account/security/change-password`
        actionDetails = [
          {
            label: t('email.Email.common.details.time'),
            value: new Date().toLocaleString(lang === 'vi' ? 'vi-VN' : 'en-US')
          },
          {
            label: t('email.Email.common.details.ipAddress'),
            value: metadata?.ipAddress ?? t('email.Email.common.locationUnknown')
          }
        ]
        break

      case SecurityAlertType.LOGIN_FROM_NEW_DEVICE:
        alertSubject = t('email.Email.securityAlert.NEW_DEVICE_LOGIN.subject')
        alertTitle = t('email.Email.securityAlert.NEW_DEVICE_LOGIN.title')
        mainMessage = t('email.Email.securityAlert.NEW_DEVICE_LOGIN.mainMessage')
        secondaryMessage = t('email.Email.securityAlert.NEW_DEVICE_LOGIN.secondaryMessage')
        actionButtonText = t('email.Email.securityAlert.NEW_DEVICE_LOGIN.buttonText')
        actionButtonUrl = `${this.frontendUrl}/account/sessions`
        actionDetails = [
          {
            label: t('email.Email.common.details.time'),
            value: new Date().toLocaleString(lang === 'vi' ? 'vi-VN' : 'en-US')
          },
          {
            label: t('email.Email.common.details.ipAddress'),
            value: metadata?.ipAddress ?? t('email.Email.common.locationUnknown')
          },
          {
            label: t('email.Email.common.details.device'),
            value: metadata?.device ?? 'Unknown'
          },
          {
            label: t('email.Email.common.details.location'),
            value: metadata?.location ?? t('email.Email.common.locationUnknown')
          }
        ]
        break

      default:
        alertSubject = t('email.Email.securityAlert.default.subject')
        alertTitle = t('email.Email.securityAlert.default.subject')
        mainMessage = ''
        secondaryMessage = undefined
        actionButtonText = undefined
        actionButtonUrl = undefined
        actionDetails = undefined
        break
    }

    return {
      to: email,
      userName,
      alertSubject,
      alertTitle,
      mainMessage,
      actionDetails,
      actionButtonText,
      actionButtonUrl,
      secondaryMessage,
      lang
    }
  }
}
