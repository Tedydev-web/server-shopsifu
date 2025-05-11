import { Injectable } from '@nestjs/common'
import { Resend } from 'resend'
import envConfig from 'src/shared/config'
import * as React from 'react'
import OTPEmail from 'emails/otp'
import PasswordChangedEmail from 'emails/password-changed'

@Injectable()
export class EmailService {
  private resend: Resend
  constructor() {
    this.resend = new Resend(envConfig.RESEND_API_KEY)
  }
  async sendOTP(payload: { email: string; code: string }) {
    const subject = `Shopsifu - Mã Xác Thực OTP Của Bạn Là ${payload.code}`
    return this.resend.emails.send({
      from: 'Shopsifu E-commerce <no-reply@shopsifu.live>',
      to: [payload.email],
      subject,
      react: <OTPEmail otpCode={payload.code} title={subject} />
    })
  }

  async sendPasswordChangedNotification(payload: { email: string; otpCode: string }) {
    const subject = 'Shopsifu - Mật khẩu của bạn đã được thay đổi'
    return this.resend.emails.send({
      from: 'Shopsifu E-commerce <no-reply@shopsifu.live>',
      to: [payload.email],
      subject,
      react: <PasswordChangedEmail title={subject} otpCode={payload.otpCode} />
    })
  }
}
