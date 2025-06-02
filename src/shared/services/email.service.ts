import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'
import { Resend } from 'resend'
import * as React from 'react'
import { render } from '@react-email/render'

// Import các template email
import OTPEmail from '../../../emails/otp'
import SecurityAlertEmail from '../../../emails/security-alert'
import { TypeOfVerificationCode } from 'src/routes/auth/constants/auth.constants'

// Các loại cảnh báo bảo mật
export enum SecurityAlertType {
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  LOGIN_FROM_NEW_DEVICE = 'LOGIN_FROM_NEW_DEVICE',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  TWO_FACTOR_ENABLED = 'TWO_FACTOR_ENABLED',
  TWO_FACTOR_DISABLED = 'TWO_FACTOR_DISABLED',
  EMAIL_CHANGED = 'EMAIL_CHANGED'
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
}

// Payload cho email OTP
export interface OtpEmailPayload {
  email: string
  otpCode: string
  otpType: string
  title?: string
}

/**
 * Dịch vụ gửi email
 */
@Injectable()
export class EmailService {
  private resend: Resend
  private readonly logger = new Logger(EmailService.name)
  private readonly isProduction: boolean
  private readonly notificationEmailFrom: string
  private readonly securityEmailFrom: string
  private readonly frontendUrl: string

  constructor(
    private readonly configService: ConfigService,
    private readonly i18nService: I18nService
  ) {
    // Khởi tạo Resend với API key từ config
    const resendApiKey = this.configService.get<string>('RESEND_API_KEY')
    if (!resendApiKey) {
      this.logger.warn('RESEND_API_KEY không được cấu hình, gửi email sẽ không hoạt động')
    }

    this.resend = new Resend(resendApiKey)
    this.isProduction =
      this.configService.get<string>('NODE_ENV') === 'production' ||
      this.configService.get<string>('NODE_ENV') === 'staging'
    this.notificationEmailFrom = `Shopsifu <${this.configService.get<string>('NOTI_MAIL_FROM_ADDRESS') || 'no-reply@shopsifu.live'}>`
    this.securityEmailFrom = `Shopsifu Security <${this.configService.get<string>('SEC_MAIL_FROM_ADDRESS') || 'security@shopsifu.live'}>`
    this.frontendUrl = this.configService.get<string>('FRONTEND_URL') || 'https://shopsifu.live'

    this.logger.debug(
      `EmailService khởi tạo với cấu hình: isProduction=${this.isProduction}, notificationEmailFrom=${this.notificationEmailFrom}, securityEmailFrom=${this.securityEmailFrom}, frontendUrl=${this.frontendUrl}`
    )
  }

  /**
   * Gửi email OTP
   */
  async sendOtpEmail(payload: OtpEmailPayload): Promise<void> {
    try {
      const { email, otpCode, otpType } = payload

      // Lấy tiêu đề email dựa trên loại OTP và ngôn ngữ
      const title = await this.getOtpTitle(otpType)

      // Render email với React
      let emailHtml: string
      try {
        emailHtml = await render(
          React.createElement(OTPEmail, {
            otpCode,
            title
          })
        )
      } catch (renderError) {
        this.logger.error(`Lỗi khi render email OTP template: ${renderError.message}`, renderError.stack)
        throw new Error(`Không thể render email template: ${renderError.message}`)
      }

      // Gửi email qua Resend trong cả môi trường production, staging và development
      // Trong development, chỉ gửi nếu tồn tại API key
      const resendApiKey = this.configService.get<string>('RESEND_API_KEY')

      if (resendApiKey && resendApiKey.trim() !== '') {
        try {
          const result = await this.resend.emails.send({
            from: this.notificationEmailFrom,
            to: [email],
            subject: title,
            html: emailHtml
          })

          this.logger.debug(`Email OTP đã gửi thành công qua Resend API: ${JSON.stringify(result)}`)
        } catch (sendError) {
          this.logger.error(`Lỗi khi gửi email qua Resend: ${sendError.message}`, sendError.stack)
          // Log thêm thông tin để debug
          this.logger.debug(`Cấu hình email: from=${this.notificationEmailFrom}, to=${email}, subject=${title}`)
          this.logger.debug(`HTML email (một phần): ${emailHtml.substring(0, 100)}...`)
          // Không throw lỗi để không ảnh hưởng đến flow đăng ký
        }
      } else {
        this.logger.warn(`Không thể gửi email - RESEND_API_KEY không được cấu hình hoặc rỗng. Mã OTP là: ${otpCode}`)
      }

      // Log thông tin chi tiết
      this.logger.log(`Đã gửi email OTP ${otpCode} đến ${email} cho mục đích ${otpType}`)
    } catch (error) {
      this.logger.error(`Lỗi tổng thể khi gửi email OTP: ${error.message}`, error.stack)
      // Không throw lỗi để không làm gián đoạn luồng xác thực
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
      // Chuẩn bị nội dung email dựa trên loại cảnh báo
      const alertContent = await this.prepareSecurityAlertContent(alertType, email, metadata)

      // Render email với React
      let emailHtml: string
      try {
        emailHtml = await render(React.createElement(SecurityAlertEmail, alertContent))
      } catch (renderError) {
        this.logger.error(`Lỗi khi render email Security Alert template: ${renderError.message}`, renderError.stack)
        throw new Error(`Không thể render email template: ${renderError.message}`)
      }

      // Gửi email qua Resend trong môi trường production hoặc staging
      if (this.isProduction) {
        try {
          const result = await this.resend.emails.send({
            from: this.securityEmailFrom,
            to: [email],
            subject: alertContent.alertSubject,
            html: emailHtml
          })

          this.logger.debug(`Email cảnh báo bảo mật đã gửi thành công: ${JSON.stringify(result)}`)
        } catch (sendError) {
          this.logger.error(`Lỗi khi gửi email cảnh báo qua Resend: ${sendError.message}`, sendError.stack)
        }
      }

      // Log thông tin trong môi trường development
      this.logger.log(`Đã gửi email thông báo bảo mật ${alertType} đến ${email}`, metadata)
    } catch (error) {
      this.logger.error(`Lỗi tổng thể khi gửi email thông báo bảo mật: ${error.message}`, error.stack)
      // Không throw lỗi để không làm gián đoạn luồng bảo mật
    }
  }

  /**
   * Lấy tiêu đề OTP dựa trên loại và ngôn ngữ
   */
  private async getOtpTitle(otpType: string): Promise<string> {
    try {
      const titleMap = {
        [TypeOfVerificationCode.REGISTER]: await this.i18nService.translate('Email.OTPSubject.Register'),
        [TypeOfVerificationCode.RESET_PASSWORD]: await this.i18nService.translate('Email.OTPSubject.ResetPassword'),
        [TypeOfVerificationCode.LOGIN]: await this.i18nService.translate('Email.OTPSubject.Default'),
        [TypeOfVerificationCode.LOGIN_2FA]: await this.i18nService.translate('Email.OTPSubject.Default'),
        [TypeOfVerificationCode.DISABLE_2FA]: await this.i18nService.translate('Email.OTPSubject.Default'),
        [TypeOfVerificationCode.SETUP_2FA]: await this.i18nService.translate('Email.OTPSubject.Default'),
        [TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP]: await this.i18nService.translate(
          'Email.OTPSubject.LoginUntrustedDevice'
        ),
        [TypeOfVerificationCode.REVERIFY_SESSION_OTP]: await this.i18nService.translate('Email.OTPSubject.Default'),
        [TypeOfVerificationCode.VERIFY_NEW_EMAIL]: await this.i18nService.translate('Email.Subject.VerifyNewEmail')
      }

      return titleMap[otpType] || (await this.i18nService.translate('Email.OTPSubject.Default'))
    } catch (error) {
      this.logger.error(`Lỗi khi lấy tiêu đề OTP: ${error.message}`, error.stack)
      return 'Mã xác minh Shopsifu' // Tiêu đề mặc định an toàn
    }
  }

  /**
   * Chuẩn bị nội dung email cảnh báo bảo mật
   */
  private async prepareSecurityAlertContent(
    alertType: SecurityAlertType,
    email: string,
    metadata?: Record<string, any>
  ): Promise<SecurityAlertEmailPayload> {
    try {
      // Thông tin cơ bản cho tất cả các loại cảnh báo
      const baseContent = {
        to: email,
        userName: metadata?.userName || email.split('@')[0]
      }

      // Chuẩn bị nội dung theo loại cảnh báo
      switch (alertType) {
        case SecurityAlertType.PASSWORD_CHANGED:
          return {
            ...baseContent,
            alertSubject: await this.i18nService.translate('Email.SecurityAlert.Subject.PasswordChanged'),
            alertTitle: await this.i18nService.translate('Email.SecurityAlert.Title.PasswordChanged'),
            mainMessage: await this.i18nService.translate('Email.SecurityAlert.MainMessage.PasswordChanged'),
            actionDetails: [
              {
                label: await this.i18nService.translate('Email.Field.Time'),
                value: new Date().toLocaleString()
              },
              {
                label: await this.i18nService.translate('Email.Field.IPAddress'),
                value: metadata?.ipAddress || 'Unknown'
              },
              {
                label: await this.i18nService.translate('Email.Field.Device'),
                value: metadata?.device || 'Unknown'
              }
            ],
            actionButtonText: await this.i18nService.translate('Email.SecurityAlert.Button.ReviewActivity'),
            actionButtonUrl: `${this.frontendUrl}/account/security`,
            secondaryMessage: await this.i18nService.translate('Email.SecurityAlert.SecondaryMessage.Password.NotYou')
          }

        case SecurityAlertType.LOGIN_FROM_NEW_DEVICE:
          return {
            ...baseContent,
            alertSubject: await this.i18nService.translate('Email.SecurityAlert.Subject.NewDeviceLogin'),
            alertTitle: await this.i18nService.translate('Email.SecurityAlert.Title.NewDeviceLogin'),
            mainMessage: await this.i18nService.translate('Email.SecurityAlert.MainMessage.NewDeviceLogin'),
            actionDetails: [
              {
                label: await this.i18nService.translate('Email.Field.Time'),
                value: new Date().toLocaleString()
              },
              {
                label: await this.i18nService.translate('Email.Field.IPAddress'),
                value: metadata?.ipAddress || 'Unknown'
              },
              {
                label: await this.i18nService.translate('Email.Field.Device'),
                value: metadata?.device || 'Unknown'
              },
              {
                label: await this.i18nService.translate('Email.Field.Location'),
                value: metadata?.location || (await this.i18nService.translate('Email.Field.LocationUnknown'))
              }
            ],
            actionButtonText: await this.i18nService.translate('Email.SecurityAlert.Button.ReviewActivity'),
            actionButtonUrl: `${this.frontendUrl}/account/sessions`,
            secondaryMessage: await this.i18nService.translate('Email.SecurityAlert.SecondaryMessage.NotYou')
          }

        // Các loại cảnh báo khác
        default:
          return {
            ...baseContent,
            alertSubject: await this.i18nService.translate('Email.SecurityAlert.Subject.Default'),
            alertTitle: await this.i18nService.translate('Email.SecurityAlert.Title.NewDeviceLogin'), // Fallback
            mainMessage: await this.i18nService.translate('Email.SecurityAlert.MainMessage.NewDeviceLogin'), // Fallback
            actionButtonText: await this.i18nService.translate('Email.SecurityAlert.Button.SecureAccount'),
            actionButtonUrl: `${this.frontendUrl}/account/security`,
            secondaryMessage: await this.i18nService.translate('Email.SecurityAlert.SecondaryMessage.NotYou')
          }
      }
    } catch (error) {
      this.logger.error(`Lỗi khi chuẩn bị nội dung email cảnh báo: ${error.message}`, error.stack)
      // Trả về nội dung cảnh báo mặc định an toàn
      return {
        to: email,
        alertSubject: 'Cảnh báo bảo mật',
        alertTitle: 'Cảnh báo bảo mật',
        mainMessage: 'Phát hiện hoạt động bảo mật quan trọng trên tài khoản của bạn.',
        secondaryMessage: 'Nếu bạn không thực hiện hành động này, vui lòng bảo vệ tài khoản của bạn ngay lập tức.'
      }
    }
  }
}
