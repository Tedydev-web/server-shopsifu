import { Injectable, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { addMilliseconds } from 'date-fns'
import { ForgotPasswordBodyDTO } from '../dtos/auth.dto'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constant'
import { EmailService } from 'src/shared/services/email.service'
import { CryptoService } from 'src/shared/services/crypto.service'
import { VerificationCodeRepository } from '../repositories/verification-code.repository'
import * as tokens from 'src/shared/constants/injection.tokens'
import { EnvConfigType } from 'src/shared/config'

@Injectable()
export class PasswordService {
  constructor(
    @Inject(tokens.SHARED_USER_REPOSITORY) private readonly userRepository: SharedUserRepository,
    @Inject(tokens.EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(tokens.CRYPTO_SERVICE) private readonly cryptoService: CryptoService,
    private readonly verificationCodeRepository: VerificationCodeRepository,
    private readonly configService: ConfigService<EnvConfigType>,
  ) {}

  async forgotPassword(body: ForgotPasswordBodyDTO) {
    const { email } = body
    const user = await this.userRepository.findUnique(email)

    // To prevent user enumeration attacks, we always return a success message,
    // regardless of whether the user exists or not. The email is only sent if the user is found.
    if (user) {
      const code = this.cryptoService.generateOTP()
      await this.emailService.sendOTP({
        email,
        code,
      })
      await this.verificationCodeRepository.create({
        email: body.email,
        code,
        type: TypeOfVerificationCode.FORGOT_PASSWORD,
        expiresAt: addMilliseconds(new Date(), this.configService.get('timeInMs').otp),
      })
    }
    return { message: 'auth.success.FORGOT_PASSWORD_SUCCESS' }
  }

  // TODO: Add resetPassword method
}
