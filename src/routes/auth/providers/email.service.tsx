import { Injectable, Logger } from '@nestjs/common'
import { Resend } from 'resend'
import envConfig from 'src/shared/config'
import * as React from 'react'
import OTPEmail from '../../../../emails/otp'
import SecurityAlertEmail from '../../../../emails/security-alert'
import { render } from '@react-email/render'

interface SecurityAlertEmailPayload {
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

@Injectable()
export class EmailService {
  private resend: Resend
  private readonly logger = new Logger(EmailService.name)

  constructor() {
    this.resend = new Resend(envConfig.RESEND_API_KEY)
  }

  async sendOTP(payload: { email: string; code: string; title: string }) {
    const emailHtml = await render(<OTPEmail otpCode={payload.code} title={payload.title} />)

    try {
      const data = await this.resend.emails.send({
        from: 'Shopsifu <no-reply@shopsifu.live>',
        to: [payload.email],
        subject: payload.title,
        html: emailHtml
      })
      return data
    } catch (error) {
      this.logger.error(`Error sending OTP email to ${payload.email}:`, error)
      throw error
    }
  }

  async sendSecurityAlertEmail(payload: SecurityAlertEmailPayload) {
    const emailHtml = await render(
      <SecurityAlertEmail
        userName={payload.userName}
        alertSubject={payload.alertSubject}
        alertTitle={payload.alertTitle}
        mainMessage={payload.mainMessage}
        actionDetails={payload.actionDetails}
        actionButtonText={payload.actionButtonText}
        actionButtonUrl={payload.actionButtonUrl}
        secondaryMessage={payload.secondaryMessage}
      />
    )

    try {
      const data = await this.resend.emails.send({
        from: 'Shopsifu Security <security@shopsifu.live>',
        to: [payload.to],
        subject: payload.alertSubject,
        html: emailHtml
      })
      return data
    } catch (error) {
      this.logger.error(`Error sending security alert email to ${payload.to}:`, error)
      throw error
    }
  }
}
