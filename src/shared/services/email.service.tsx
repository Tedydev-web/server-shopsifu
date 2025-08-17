import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Resend } from 'resend'

import * as React from 'react'
import { OTPEmail } from '../emails/otp'

@Injectable()
export class EmailService {
  private resend: Resend

  constructor(private readonly configService: ConfigService) {
    const apiKey = this.configService.get<string>('RESEND_API_KEY')
    if (!apiKey) {
      throw new Error('RESEND_API_KEY is not configured')
    }
    this.resend = new Resend(apiKey)
  }

  async sendOTP(payload: { email: string; code: string }) {
    const subject = 'Mã OTP'
    return this.resend.emails.send({
      from: 'Shopsifu Ecommerce <no-reply@shopsifu.live>',
      to: [payload.email],
      subject,
      react: <OTPEmail otpCode={payload.code} title={subject} />
    })
  }
}
