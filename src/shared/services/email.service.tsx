import { Injectable } from '@nestjs/common'
import { Resend } from 'resend'
import envConfig from 'src/shared/config'
import * as React from 'react'
import OTPEmail from 'emails/otp'

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
}
