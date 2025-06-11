// ================================================================
// NestJS Dependencies
// ================================================================
import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService, I18nContext } from 'nestjs-i18n'

// ================================================================
// External Libraries
// ================================================================
import { Resend } from 'resend'
import * as React from 'react'

// ================================================================
// Internal Types & Constants
// ================================================================
import { TypeOfVerificationCodeType } from 'src/routes/auth/auth.constants'

// ================================================================
// Email Components
// ================================================================
import { OtpEmail, OtpEmailProps } from 'emails/otp-email'
import { RecoveryCodesEmail, RecoveryCodesEmailProps } from 'emails/recovery-codes-email'
import { SecurityLoginAlert, SecurityLoginAlertProps } from 'emails/security-login-alert'
import { DeviceTrustAlert, DeviceTrustAlertProps } from 'emails/device-trust-alert'
import { PasswordResetAlert, PasswordResetAlertProps } from 'emails/password-reset-alert'
import { TwoFactorAlert, TwoFactorAlertProps } from 'emails/two-factor-alert'
import { SessionRevokeAlert, SessionRevokeAlertProps } from 'emails/session-revoke-alert'
import { AccountLockedEmail, AccountLockedEmailProps } from 'emails/account-locked-email'
import { SuspiciousActivityEmail, SuspiciousActivityEmailProps } from 'emails/suspicious-activity-email'
import { AccountLinkAlert, AccountLinkAlertProps } from 'emails/account-link-alert'
import { WelcomeEmail, WelcomeEmailProps } from 'emails/welcome-email'
import { UserCreatedAlert, UserCreatedAlertProps } from 'emails/user-created-alert'
import { UserUpdatedAlert, UserUpdatedAlertProps } from 'emails/user-updated-alert'
import { UserDeletedAlert, UserDeletedAlertProps } from 'emails/user-deleted-alert'

// ================================================================
// Type Exports & Interfaces
// ================================================================
// Re-export props for external use
export {
  OtpEmailProps,
  RecoveryCodesEmailProps,
  SecurityLoginAlertProps,
  DeviceTrustAlertProps,
  PasswordResetAlertProps,
  TwoFactorAlertProps,
  SessionRevokeAlertProps,
  AccountLockedEmailProps,
  SuspiciousActivityEmailProps,
  AccountLinkAlertProps,
  WelcomeEmailProps,
  UserCreatedAlertProps,
  UserUpdatedAlertProps,
  UserDeletedAlertProps
}

type TranslateFunction = (key: string, options?: any) => string

interface BaseEmailPayload<T> {
  to: string
  subjectKey: string
  subjectArgs?: Record<string, any>
  component: React.ComponentType<T>
  props: T
  lang?: 'vi' | 'en'
  from?: string
}

/**
 * Service quản lý việc gửi email với hỗ trợ đa ngôn ngữ và template
 * Sử dụng Resend API để gửi email và React components làm template
 */
@Injectable()
export class EmailService {
  private resend: Resend | undefined
  private readonly logger = new Logger(EmailService.name)
  private readonly notificationEmailFrom: string
  private readonly securityEmailFrom: string
  private readonly frontendUrl: string

  constructor(
    private readonly configService: ConfigService,
    private readonly i18nService: I18nService
  ) {
    // Khởi tạo Resend API client nếu có API key
    const apiKey = this.configService.get<string>('RESEND_API_KEY')
    if (apiKey) {
      this.resend = new Resend(apiKey)
      this.logger.log('Resend API client khởi tạo thành công.')
    } else {
      this.logger.warn('RESEND_API_KEY chưa được cấu hình. Dịch vụ email sẽ bị vô hiệu hóa.')
    }

    // Cấu hình các địa chỉ email gửi
    this.notificationEmailFrom =
      this.configService.get<string>('NOTIFICATION_EMAIL_FROM') ?? 'notification@shopsifu.live'
    this.securityEmailFrom = this.configService.get<string>('SECURITY_EMAIL_FROM') ?? 'security@shopsifu.live'
    this.frontendUrl = this.configService.get<string>('FRONTEND_URL') ?? 'http://localhost:8000'
  }

  // ================================================================
  // Private Methods - Utility & Helper Functions
  // ================================================================

  /**
   * Đảm bảo ngôn ngữ hợp lệ, fallback về 'vi' nếu không hợp lệ
   * @param preferredLang - Ngôn ngữ ưa thích
   * @returns Ngôn ngữ hợp lệ ('vi' hoặc 'en')
   */
  private getSafeLang(preferredLang?: 'vi' | 'en'): 'vi' | 'en' {
    if (preferredLang && ['vi', 'en'].includes(preferredLang)) {
      return preferredLang
    }
    const langFromContext = I18nContext.current()?.lang
    if (langFromContext === 'vi' || langFromContext === 'en') {
      return langFromContext
    }
    return 'vi' // Mặc định tiếng Việt
  }

  /**
   * Phương thức core để gửi email với React component template
   * Xử lý việc render component, dịch subject và gửi qua Resend API
   * @param payload - Thông tin email và component để render
   */
  private async send<T>(payload: BaseEmailPayload<T>): Promise<void> {
    if (!this.resend) {
      this.logger.warn(`Gửi email bị vô hiệu hóa. Đã bỏ qua email gửi tới ${payload.to}.`)
      return
    }

    const lang = this.getSafeLang(payload.lang)
    const t: TranslateFunction = (key, options) => this.i18nService.t(key, { lang, ...options })
    const subject = t(payload.subjectKey, payload.subjectArgs)

    try {
      const { data, error } = await this.resend.emails.send({
        from: payload.from || this.notificationEmailFrom,
        to: payload.to,
        subject,
        react: React.createElement(payload.component, payload.props)
      })

      if (error) {
        this.logger.error(`Resend API trả về lỗi cho người nhận ${payload.to}`, error)
        return
      }

      this.logger.log(`Email gửi thành công tới ${payload.to} với subject: ${subject}, ID: ${data?.id}`)
    } catch (error) {
      this.logger.error(`Gửi email thất bại tới ${payload.to}. Subject: ${subject}`, error.stack)
      // Không re-throw để tránh làm crash caller
    }
  }

  // ================================================================
  // Public Methods - Email Sending API
  // ================================================================

  /**
   * Gửi email OTP cho xác thực đa yếu tố hoặc xác minh tài khoản
   * @param to - Địa chỉ email người nhận
   * @param otpType - Loại OTP (LOGIN, REGISTER, RECOVERY, v.v.)
   * @param props - Thông tin cần thiết cho email (code, userName, etc.)
   */
  async sendOtpEmail(
    to: string,
    otpType: TypeOfVerificationCodeType,
    props: Omit<OtpEmailProps, 'headline' | 'content' | 'codeLabel' | 'validity' | 'disclaimer' | 'greeting'>
  ): Promise<void> {
    const lang = this.getSafeLang(props.lang)
    const t: TranslateFunction = (key, options) => this.i18nService.t(key, { lang, ...options })

    const fullProps: OtpEmailProps = {
      ...props,
      greeting: t('email.Email.common.greeting', {
        args: { userName: props.userName }
      }),
      headline: t(`email.Email.otp.${otpType}.headline`),
      content: t('email.Email.otp.common.content'),
      codeLabel: t('email.Email.otp.common.codeLabel'),
      validity: t('email.Email.otp.common.validity', { args: { minutes: 5 } }),
      disclaimer: t('email.Email.otp.common.disclaimer')
    }

    await this.send({
      to,
      subjectKey: `email.Email.otp.${otpType}.subject`,
      component: OtpEmail,
      props: fullProps,
      lang
    })
  }

  /**
   * Gửi email chứa mã recovery codes cho 2FA
   * @param to - Địa chỉ email người nhận
   * @param props - Thông tin recovery codes và user
   */
  async sendRecoveryCodesEmail(
    to: string,
    props: Omit<
      RecoveryCodesEmailProps,
      'headline' | 'content' | 'codesLabel' | 'warning' | 'buttonText' | 'greeting' | 'buttonUrl' | 'downloadUrl'
    >
  ): Promise<void> {
    const lang = this.getSafeLang(props.lang)
    const t: TranslateFunction = (key, options) => this.i18nService.t(key, { lang, ...options })

    const fullProps: RecoveryCodesEmailProps = {
      ...props,
      buttonUrl: `${this.frontendUrl}/account/security`,
      downloadUrl: `${this.frontendUrl}/account/security/download-recovery-codes`,
      greeting: t('email.Email.common.greeting', {
        args: { userName: props.userName }
      }),
      headline: t('email.Email.recoveryCodes.headline'),
      content: t('email.Email.recoveryCodes.content'),
      codesLabel: t('email.Email.recoveryCodes.codesLabel'),
      warning: t('email.Email.recoveryCodes.warning'),
      buttonText: t('email.Email.recoveryCodes.buttonText')
    }

    await this.send({
      to,
      subjectKey: 'email.Email.recoveryCodes.subject',
      component: RecoveryCodesEmail,
      props: fullProps,
      from: this.securityEmailFrom,
      lang
    })
  }

  // ================================================================
  // Private Methods - Security Alert Helper
  // ================================================================

  /**
   * Helper method để gửi các loại security alert email
   * Tự động điền các field title, greeting, message và buttonText từ i18n
   * @param to - Địa chỉ email người nhận
   * @param alertType - Loại alert (DEVICE_TRUSTED, PASSWORD_CHANGED, etc.)
   * @param component - React component để render email
   * @param props - Props cho component (không bao gồm các field tự động điền)
   */
  private async sendSecurityAlert<T extends { lang?: 'vi' | 'en'; userName: string; greeting?: string }>(
    to: string,
    alertType: string,
    component: React.ComponentType<T>,
    props: Omit<T, 'title' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'greeting'>
  ): Promise<void> {
    const lang = this.getSafeLang(props.lang)
    const t: TranslateFunction = (key, options) => this.i18nService.t(key, { lang, ...options })

    const fullProps = {
      ...props,
      greeting: t('email.Email.common.greeting', { args: { userName: props.userName } }),
      title: t(`email.Email.securityAlert.${alertType}.title`),
      mainMessage: t(`email.Email.securityAlert.${alertType}.mainMessage`, props),
      secondaryMessage: t(`email.Email.securityAlert.${alertType}.secondaryMessage`, props),
      buttonText: t(`email.Email.securityAlert.${alertType}.buttonText`)
    } as unknown as T

    await this.send({
      to,
      subjectKey: `email.Email.securityAlert.${alertType}.subject`,
      from: this.securityEmailFrom,
      component,
      props: fullProps,
      lang
    })
  }

  // ================================================================
  // Public Methods - Security Alert Emails
  // ================================================================

  /**
   * Gửi email thông báo đăng nhập từ thiết bị mới chưa được tin cậy
   * @param to - Địa chỉ email người nhận
   * @param props - Thông tin về thiết bị và vị trí đăng nhập
   */
  async sendNewDeviceLoginEmail(
    to: string,
    props: Omit<
      SecurityLoginAlertProps,
      'title' | 'greeting' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'buttonUrl'
    >
  ): Promise<void> {
    await this.sendSecurityAlert(to, 'NEW_DEVICE_LOGIN', SecurityLoginAlert, {
      ...props,
      buttonUrl: `${this.frontendUrl}/account/sessions`
    })
  }

  /**
   * Gửi email thông báo thay đổi trạng thái tin cậy của thiết bị
   * @param to - Địa chỉ email người nhận
   * @param props - Thông tin về thiết bị và action (trusted/untrusted)
   */
  async sendDeviceTrustChangeEmail(
    to: string,
    props: Omit<
      DeviceTrustAlertProps,
      'title' | 'greeting' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'buttonUrl'
    >
  ): Promise<void> {
    const alertType = props.action === 'trusted' ? 'DEVICE_TRUSTED' : 'DEVICE_UNTRUSTED'
    await this.sendSecurityAlert(to, alertType, DeviceTrustAlert, {
      ...props,
      buttonUrl: `${this.frontendUrl}/account/sessions`
    })
  }

  /**
   * Gửi email thông báo mật khẩu đã được thay đổi
   * @param to - Địa chỉ email người nhận
   * @param props - Thông tin về việc đổi mật khẩu
   */
  async sendPasswordChangedEmail(
    to: string,
    props: Omit<
      PasswordResetAlertProps,
      'title' | 'greeting' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'buttonUrl'
    >
  ): Promise<void> {
    await this.sendSecurityAlert(to, 'PASSWORD_CHANGED', PasswordResetAlert, {
      ...props,
      buttonUrl: `${this.frontendUrl}/account/security`
    })
  }

  /**
   * Gửi email thông báo thay đổi trạng thái 2FA (bật/tắt)
   * @param to - Địa chỉ email người nhận
   * @param props - Thông tin về action 2FA (enabled/disabled)
   */
  async sendTwoFactorStatusChangedEmail(
    to: string,
    props: Omit<
      TwoFactorAlertProps,
      'title' | 'greeting' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'buttonUrl'
    >
  ): Promise<void> {
    const alertType = props.action === 'enabled' ? 'TWO_FACTOR_ENABLED' : 'TWO_FACTOR_DISABLED'
    await this.sendSecurityAlert(to, alertType, TwoFactorAlert, {
      ...props,
      buttonUrl: `${this.frontendUrl}/account/security`
    })
  }

  async sendSessionRevokeEmail(
    to: string,
    props: Omit<
      SessionRevokeAlertProps,
      'title' | 'greeting' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'buttonUrl'
    >
  ): Promise<void> {
    await this.sendSecurityAlert(to, 'SESSIONS_REVOKED', SessionRevokeAlert, {
      ...props,
      buttonUrl: `${this.frontendUrl}/account/sessions`
    })
  }

  async sendAccountLinkStatusChangeEmail(
    to: string,
    props: Omit<
      AccountLinkAlertProps,
      'title' | 'greeting' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'buttonUrl'
    >
  ): Promise<void> {
    const alertType = props.action === 'linked' ? 'ACCOUNT_LINKED' : 'ACCOUNT_UNLINKED'
    await this.sendSecurityAlert(to, alertType, AccountLinkAlert, {
      ...props,
      buttonUrl: `${this.frontendUrl}/account/security`
    })
  }

  async sendDeviceLimitWarningEmail(
    to: string,
    props: Omit<
      SecurityLoginAlertProps,
      'title' | 'greeting' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'buttonUrl'
    >
  ): Promise<void> {
    await this.sendSecurityAlert(to, 'DEVICE_LIMIT_WARNING', SecurityLoginAlert, {
      ...props,
      buttonUrl: `${this.frontendUrl}/account/sessions`
    })
  }

  async sendAccountLockedEmail(
    to: string,
    props: Omit<
      AccountLockedEmailProps,
      'title' | 'greeting' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'buttonUrl'
    >
  ): Promise<void> {
    await this.sendSecurityAlert(to, 'ACCOUNT_LOCKED', AccountLockedEmail, {
      ...props,
      buttonUrl: `${this.frontendUrl}/reset-password`
    })
  }

  async sendSuspiciousActivityEmail(
    to: string,
    props: Omit<
      SuspiciousActivityEmailProps,
      'title' | 'greeting' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'buttonUrl'
    >
  ): Promise<void> {
    await this.sendSecurityAlert(to, 'SUSPICIOUS_ACTIVITY', SuspiciousActivityEmail, {
      ...props,
      buttonUrl: `${this.frontendUrl}/account/activity`
    })
  }

  async sendWelcomeEmail(
    to: string,
    props: Omit<WelcomeEmailProps, 'headline' | 'content' | 'buttonText' | 'greeting' | 'buttonUrl'>
  ): Promise<void> {
    const lang = this.getSafeLang(props.lang)
    const t: TranslateFunction = (key, options) => this.i18nService.t(key, { lang, ...options })

    const fullProps: WelcomeEmailProps = {
      ...props,
      buttonUrl: `${this.frontendUrl}/dashboard`,
      greeting: t('email.Email.common.greeting', {
        args: { userName: props.userName }
      }),
      headline: t('email.Email.welcome.headline'),
      content: t('email.Email.welcome.content'),
      buttonText: t('email.Email.welcome.buttonText')
    }

    await this.send({
      to,
      subjectKey: 'email.Email.welcome.subject',
      component: WelcomeEmail,
      props: fullProps,
      lang
    })
  }

  // ================================================================
  // Public Methods - User Management Alert Emails
  // ================================================================

  /**
   * Gửi email thông báo tạo user mới cho admin và các stakeholder
   * @param to - Địa chỉ email người nhận
   * @param props - Thông tin về user được tạo và admin thực hiện
   */
  async sendUserCreatedAlert(
    to: string,
    props: Omit<
      UserCreatedAlertProps,
      'title' | 'greeting' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'buttonUrl'
    >
  ): Promise<void> {
    const lang = this.getSafeLang(props.lang)
    const t: TranslateFunction = (key, options) => this.i18nService.t(key, { lang, ...options })

    const fullProps: UserCreatedAlertProps = {
      ...props,
      buttonUrl: `${this.frontendUrl}/admin/users`,
      greeting: t('email.Email.common.greeting', {
        args: { userName: props.userName }
      }),
      title: t('email.Email.userManagement.USER_CREATED.title'),
      mainMessage: t('email.Email.userManagement.USER_CREATED.mainMessage'),
      secondaryMessage: t('email.Email.userManagement.USER_CREATED.secondaryMessage'),
      buttonText: t('email.Email.userManagement.USER_CREATED.buttonText')
    }

    await this.send({
      to,
      subjectKey: 'email.Email.userManagement.USER_CREATED.subject',
      from: this.securityEmailFrom,
      component: UserCreatedAlert,
      props: fullProps,
      lang
    })
  }

  /**
   * Gửi email thông báo cập nhật thông tin user
   * @param to - Địa chỉ email người nhận
   * @param props - Thông tin về user được cập nhật và các thay đổi
   */
  async sendUserUpdatedAlert(
    to: string,
    props: Omit<
      UserUpdatedAlertProps,
      'title' | 'greeting' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'buttonUrl'
    >
  ): Promise<void> {
    const lang = this.getSafeLang(props.lang)
    const t: TranslateFunction = (key, options) => this.i18nService.t(key, { lang, ...options })

    const fullProps: UserUpdatedAlertProps = {
      ...props,
      buttonUrl: `${this.frontendUrl}/admin/users/${props.userInfo.email}`,
      greeting: t('email.Email.common.greeting', {
        args: { userName: props.userName }
      }),
      title: t('email.Email.userManagement.USER_UPDATED.title'),
      mainMessage: t('email.Email.userManagement.USER_UPDATED.mainMessage'),
      secondaryMessage: t('email.Email.userManagement.USER_UPDATED.secondaryMessage'),
      buttonText: t('email.Email.userManagement.USER_UPDATED.buttonText')
    }

    await this.send({
      to,
      subjectKey: 'email.Email.userManagement.USER_UPDATED.subject',
      from: this.securityEmailFrom,
      component: UserUpdatedAlert,
      props: fullProps,
      lang
    })
  }

  /**
   * Gửi email cảnh báo xóa user - hành động quan trọng
   * @param to - Địa chỉ email người nhận
   * @param props - Thông tin về user bị xóa và admin thực hiện
   */
  async sendUserDeletedAlert(
    to: string,
    props: Omit<
      UserDeletedAlertProps,
      'title' | 'greeting' | 'mainMessage' | 'secondaryMessage' | 'buttonText' | 'buttonUrl'
    >
  ): Promise<void> {
    const lang = this.getSafeLang(props.lang)
    const t: TranslateFunction = (key, options) => this.i18nService.t(key, { lang, ...options })

    const fullProps: UserDeletedAlertProps = {
      ...props,
      buttonUrl: `${this.frontendUrl}/admin/audit-logs`,
      greeting: t('email.Email.common.greeting', {
        args: { userName: props.userName }
      }),
      title: t('email.Email.userManagement.USER_DELETED.title'),
      mainMessage: t('email.Email.userManagement.USER_DELETED.mainMessage'),
      secondaryMessage: t('email.Email.userManagement.USER_DELETED.secondaryMessage'),
      buttonText: t('email.Email.userManagement.USER_DELETED.buttonText')
    }

    await this.send({
      to,
      subjectKey: 'email.Email.userManagement.USER_DELETED.subject',
      from: this.securityEmailFrom,
      component: UserDeletedAlert,
      props: fullProps,
      lang
    })
  }
}
