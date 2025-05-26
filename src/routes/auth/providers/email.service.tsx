import { Injectable, Logger } from '@nestjs/common'
import { Resend } from 'resend'
import envConfig from 'src/shared/config'
import * as React from 'react'
import OTPEmail from '../../../../emails/otp' // Updated import path
import SecurityAlertEmail from '../../../../emails/security-alert' // Added import
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
    const { email, code, title } = payload
    if (envConfig.NODE_ENV === 'test') {
      this.logger.log(`OTP for ${email} (TEST ENV): ${code}`)
      return { id: 'test_email_id' } // Mock response for test environment
    }

    if (!envConfig.NOTI_EMAIL_FROM_ADDRESS) {
      this.logger.error('NOTI_EMAIL_FROM_ADDRESS is not configured. Cannot send OTP email.')
      // Throw an error here because this is a configuration issue that prevents sending.
      throw new Error('Email from address is not configured.')
    }

    try {
      const { data, error } = await this.resend.emails.send({
        from: `Shopsifu <${envConfig.NOTI_EMAIL_FROM_ADDRESS}>`,
        to: email,
        subject: title,
        html: `Your OTP code is: <strong>${code}</strong>. It will expire in ${envConfig.OTP_EXPIRES_IN}.`
      })

      if (error) {
        this.logger.error(`Failed to send OTP email to ${email}. Resend error:`, error)
        throw new Error(error.message || 'Resend API error during OTP sending.')
      }

      // Log the ID if data is available and has an id
      if (data && data.id) {
        this.logger.log(`OTP email sent to ${email}, ID: ${data.id}`)
      } else {
        this.logger.warn(`OTP email to ${email} - Resend returned success but no ID found in data. Data:`, data)
      }
      return { data, error } // Return the whole response object
    } catch (error) {
      // Catch any other unexpected errors (e.g., network issues before Resend call)
      this.logger.error(`Unexpected error sending OTP email to ${email}`, error)
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
      const { data, error } = await this.resend.emails.send({
        from: `Shopsifu Security <${envConfig.SEC_EMAIL_FROM_ADDRESS}>`, // Using a different sender for security alerts
        to: [payload.to],
        subject: payload.alertSubject,
        html: emailHtml
      })

      if (error) {
        this.logger.error(`Failed to send security alert email to ${payload.to}. Resend error:`, error)
        // Do not re-throw here for security alerts, but ensure comprehensive logging
        return { data, error }
      }

      if (data && data.id) {
        this.logger.log(`Security alert email sent successfully to ${payload.to}, ID: ${data.id}`)
      } else {
        this.logger.warn(
          `Security alert email to ${payload.to} - Resend returned success but no ID found in data. Data:`,
          data
        )
      }
      return { data, error }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      const errorStack = error instanceof Error ? error.stack : undefined
      this.logger.error(`Failed to send security alert email to ${payload.to}: ${errorMessage}`, errorStack)
      // Do not re-throw here to prevent blocking the main flow,
      // but ensure the error is logged comprehensively.
    }
  }
}
