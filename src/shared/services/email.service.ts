import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Resend } from 'resend'
import { I18nService, I18nContext } from 'nestjs-i18n'
import * as React from 'react'

import { TypeOfVerificationCodeType } from 'src/routes/auth/auth.constants'

// --- Import Email Components ---
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
  WelcomeEmailProps
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
    const apiKey = this.configService.get<string>('RESEND_API_KEY')
    if (apiKey) {
      this.resend = new Resend(apiKey)
      this.logger.log('Resend API client initialized successfully.')
    } else {
      this.logger.warn('RESEND_API_KEY is not configured. Email services will be disabled.')
    }
    this.notificationEmailFrom =
      this.configService.get<string>('NOTIFICATION_EMAIL_FROM') ?? 'notification@shopsifu.live'
    this.securityEmailFrom = this.configService.get<string>('SECURITY_EMAIL_FROM') ?? 'security@shopsifu.live'
    this.frontendUrl = this.configService.get<string>('FRONTEND_URL') ?? 'http://localhost:8000'
  }

  private getSafeLang(preferredLang?: 'vi' | 'en'): 'vi' | 'en' {
    if (preferredLang && ['vi', 'en'].includes(preferredLang)) {
      return preferredLang
    }
    const langFromContext = I18nContext.current()?.lang
    if (langFromContext === 'vi' || langFromContext === 'en') {
      return langFromContext
    }
    return 'vi'
  }

  private async send<T>(payload: BaseEmailPayload<T>): Promise<void> {
    if (!this.resend) {
      this.logger.warn(`Email sending is disabled. Would have sent to ${payload.to}.`)
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
        throw new Error(JSON.stringify(error))
      }

      this.logger.log(`Email sent successfully to ${payload.to} with subject: ${subject}`)
    } catch (error) {
      this.logger.error(`Failed to send email to ${payload.to}. Subject: ${subject}`, error.stack)
      // Do not re-throw to avoid crashing the caller
    }
  }

  // --- PUBLIC METHODS ---

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

  // --- SECURITY ALERTS ---

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
}
