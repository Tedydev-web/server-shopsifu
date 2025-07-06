import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { addMilliseconds } from 'date-fns'
import { TypeOfVerificationCode, TypeOfVerificationCodeType } from 'src/shared/constants/auth.constant'
import { CryptoService } from 'src/shared/services/crypto.service'
import { EmailService } from 'src/shared/services/email.service'
import { VerificationCodeRepository } from '../repositories/verification-code.repository'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { SendOTPBodyDTO } from '../dtos/auth.dto'
import { EnvConfigType } from 'src/shared/config'
import { SltService } from 'src/shared/services/slt.service'
import { CookieService } from 'src/shared/services/cookie.service'
import { Request, Response } from 'express'
import { CookieNames } from 'src/shared/constants/cookie.constant'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'
import { EmailAlreadyExistsException, InvalidOTPException, OTPExpiredException, StateTokenMissingException } from '../auth.error'

@Injectable()
export class OtpService {
  constructor(
    private readonly userRepository: SharedUserRepository,
    private readonly cryptoService: CryptoService,
    private readonly emailService: EmailService,
    private readonly verificationCodeRepository: VerificationCodeRepository,
    private readonly configService: ConfigService<EnvConfigType>,
    private readonly sltService: SltService,
    private readonly cookieService: CookieService,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async sendOTP(body: SendOTPBodyDTO, req: Request, res: Response) {
    const user = await this.userRepository.findUnique({ email: body.email })
    if (body.type === TypeOfVerificationCode.REGISTER && user) {
      throw EmailAlreadyExistsException
    }
    if (body.type === TypeOfVerificationCode.FORGOT_PASSWORD && !user) {
      // Don't throw an error to prevent user enumeration attacks
      return { message: this.i18n.t('auth.auth.success.SEND_OTP_SUCCESS') }
    }

    const code = this.cryptoService.generateOTP()
    const userId = user ? user.id : 0 // Use a placeholder ID for registration flow

    // Create a state token
    const slt = await this.sltService.createStateToken(userId, body.type, req)

    // Set SLT in a secure cookie
    this.cookieService.set(res, 'slt', slt)

    await this.verificationCodeRepository.create({
      email: body.email,
      code,
      type: body.type,
      expiresAt: addMilliseconds(new Date(), this.configService.get('timeouts').otp)
    })
    await this.emailService.sendOTP({
      email: body.email,
      code
    })
    return {
      message: this.i18n.t('auth.auth.success.SEND_OTP_SUCCESS')
    }
  }

  async validateVerificationCode({
    email,
    code,
    type,
    req
  }: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
    req: Request
  }) {
    // 1. Validate the SLT
    const sltCookie = req.cookies[CookieNames.SLT]
    if (!sltCookie) {
      throw StateTokenMissingException
    }
    await this.sltService.validateAndGetContext(sltCookie, req, type)

    // 2. Validate the OTP
    const verificationCode = await this.verificationCodeRepository.findUnique({
      email,
      code,
      type
    })
    if (!verificationCode) {
      throw InvalidOTPException
    }
    if (verificationCode.expiresAt < new Date()) {
      await this.verificationCodeRepository.delete({ email, code, type })
      throw OTPExpiredException
    }

    // Delete the code after successful validation
    await this.verificationCodeRepository.delete({ email, code, type })

    return verificationCode
  }
}
