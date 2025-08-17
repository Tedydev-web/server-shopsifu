import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import * as OTPAuth from 'otpauth'

@Injectable()
export class TwoFactorService {
  constructor(private readonly configService: ConfigService) {}

  private createTOTP(email: string, secret?: string) {
    return new OTPAuth.TOTP({
      issuer: this.configService.get<string>('APP_NAME'),
      label: email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: secret || new OTPAuth.Secret()
    })
  }

  generateTOTPSecret(email: string) {
    const totp = this.createTOTP(email)
    return {
      secret: totp.secret.base32,
      uri: totp.toString()
    }
  }

  verifyTOTP({ email, token, secret }: { email: string; secret: string; token: string }): boolean {
    const totp = this.createTOTP(email, secret)
    const delta = totp.validate({ token, window: 1 })
    return delta !== null
  }
}
