import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'
import { Resend } from 'resend'
import * as React from 'react'
import { render } from '@react-email/render'
import { I18nContext } from 'nestjs-i18n'

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
    // Khởi tạo Resend API client
    const resendApiKey = this.configService.get<string>('RESEND_API_KEY')

    if (!resendApiKey) {
      this.logger.warn('RESEND_API_KEY chưa được cấu hình. Email sẽ không được gửi.')
    } else {
      this.resend = new Resend(resendApiKey)
      this.logger.log('Resend API client đã khởi tạo thành công.')
    }

    // Cấu hình khác
    this.isProduction = ['production', 'staging'].includes(this.configService.get<string>('NODE_ENV') || 'development')
    this.notificationEmailFrom =
      this.configService.get<string>('NOTI_MAIL_FROM_ADDRESS') || 'Shopsifu <no-reply@shopsifu.live>'
    this.securityEmailFrom =
      this.configService.get<string>('SEC_MAIL_FROM_ADDRESS') || 'Shopsifu Security <security@shopsifu.live>'
    this.frontendUrl = this.configService.get<string>('FRONTEND_URL') || 'https://localhost:8000'

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
      const lang = I18nContext.current()?.lang || 'vi'

      // Dịch tiêu đề
      const titleKey = `Email.OTPSubject.${otpType}`
      const title: string = await this.i18nService.translate(titleKey, { lang })

      // Dịch tiêu đề chính và nội dung
      const headingText: string = await this.i18nService.translate(`Email.otp.${otpType.toLowerCase()}.headline`, {
        lang
      })
      const contentText: string = await this.i18nService.translate(`Email.otp.${otpType.toLowerCase()}.content`, {
        lang
      })
      const codeLabel: string = await this.i18nService.translate('Email.otp.codeLabel', { lang })
      const validityText: string = await this.i18nService.translate('Email.otp.validity', { lang })

      // Dịch phần footer
      const disclaimerText: string = await this.i18nService.translate('Email.disclaimer', { lang })
      const contactUsText: string = await this.i18nService.translate('Email.common.contactUs', { lang })
      const copyrightText: string = await this.i18nService.translate('Email.common.footer.copyright', {
        lang,
        args: { year: new Date().getFullYear().toString() }
      })

      // Gửi email với nội dung đã được dịch
      await this.resend.emails.send({
        from: this.notificationEmailFrom,
        to: email,
        subject: title,
        react: OTPEmail({
          otpCode,
          title,
          headingText,
          contentText,
          codeLabel,
          validityText,
          disclaimerText,
          contactUsText,
          copyrightText
        })
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

      // Kiểm tra resendApiKey trước khi gửi
      if (this.resend) {
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
      } else {
        this.logger.warn(
          `Resend API chưa được cấu hình. Email không được gửi đi (alertType: ${alertType}, to: ${email})`
        )
      }

      // Log thông tin
      this.logger.log(`Đã gửi email thông báo bảo mật ${alertType} đến ${email}`, metadata)
    } catch (error) {
      this.logger.error(`Lỗi tổng thể khi gửi email thông báo bảo mật: ${error.message}`, error.stack)
      // Không throw lỗi để không làm gián đoạn luồng bảo mật
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
    const lang = I18nContext.current()?.lang || 'vi'
    const userName = metadata?.userName

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
        alertSubject = await this.i18nService.translate('Email.SecurityAlert.Subject.PasswordChanged', { lang })
        alertTitle = await this.i18nService.translate('Email.SecurityAlert.Title.PasswordChanged', { lang })
        mainMessage = await this.i18nService.translate('Email.SecurityAlert.MainMessage.PasswordChanged', { lang })
        secondaryMessage = await this.i18nService.translate('Email.SecurityAlert.SecondaryMessage.Password.NotYou', {
          lang
        })
        actionButtonText = await this.i18nService.translate('Email.SecurityAlert.Button.ChangePassword', { lang })
        actionButtonUrl = `${this.frontendUrl}/account/security/change-password`
        actionDetails = [
          {
            label: await this.i18nService.translate('Email.Field.Time', { lang }),
            value: new Date().toLocaleString(lang === 'vi' ? 'vi-VN' : 'en-US')
          },
          {
            label: await this.i18nService.translate('Email.Field.IPAddress', { lang }),
            value: metadata?.ipAddress || 'Unknown'
          }
        ]
        break

      case SecurityAlertType.LOGIN_FROM_NEW_DEVICE:
        alertSubject = await this.i18nService.translate('Email.SecurityAlert.Subject.NewDeviceLogin', { lang })
        alertTitle = await this.i18nService.translate('Email.SecurityAlert.Title.NewDeviceLogin', { lang })
        mainMessage = await this.i18nService.translate('Email.SecurityAlert.MainMessage.NewDeviceLogin', { lang })
        secondaryMessage = await this.i18nService.translate('Email.SecurityAlert.SecondaryMessage.NotYou', { lang })
        actionButtonText = await this.i18nService.translate('Email.SecurityAlert.Button.ReviewActivity', { lang })
        actionButtonUrl = `${this.frontendUrl}/account/sessions`
        actionDetails = [
          {
            label: await this.i18nService.translate('Email.Field.Time', { lang }),
            value: new Date().toLocaleString(lang === 'vi' ? 'vi-VN' : 'en-US')
          },
          {
            label: await this.i18nService.translate('Email.Field.IPAddress', { lang }),
            value: metadata?.ipAddress || 'Unknown'
          },
          {
            label: await this.i18nService.translate('Email.Field.Device', { lang }),
            value: metadata?.device || 'Unknown'
          },
          {
            label: await this.i18nService.translate('Email.Field.Location', { lang }),
            value: metadata?.location || (await this.i18nService.translate('Email.Field.LocationUnknown', { lang }))
          }
        ]
        break

      default:
        alertSubject = await this.i18nService.translate('Email.SecurityAlert.Subject.Default', { lang })
        alertTitle = await this.i18nService.translate('Email.SecurityAlert.Title.NewDeviceLogin', { lang })
        mainMessage = await this.i18nService.translate('Email.SecurityAlert.MainMessage.NewDeviceLogin', { lang })
        secondaryMessage = await this.i18nService.translate('Email.SecurityAlert.SecondaryMessage.NotYou', { lang })
        actionButtonText = await this.i18nService.translate('Email.SecurityAlert.Button.SecureAccount', { lang })
        actionButtonUrl = `${this.frontendUrl}/account/security`
        actionDetails = [
          {
            label: await this.i18nService.translate('Email.Field.Time', { lang }),
            value: new Date().toLocaleString(lang === 'vi' ? 'vi-VN' : 'en-US')
          },
          {
            label: await this.i18nService.translate('Email.Field.IPAddress', { lang }),
            value: metadata?.ipAddress || 'Unknown'
          },
          {
            label: await this.i18nService.translate('Email.Field.Device', { lang }),
            value: metadata?.device || 'Unknown'
          },
          {
            label: await this.i18nService.translate('Email.Field.Location', { lang }),
            value: metadata?.location || (await this.i18nService.translate('Email.Field.LocationUnknown', { lang }))
          }
        ]
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
      secondaryMessage
    }
  }
}
