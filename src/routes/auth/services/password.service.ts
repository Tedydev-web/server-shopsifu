import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { Response } from 'express'
import { AuthError } from '../auth.error'
import { AuthVerificationService } from './auth-verification.service'
import { UserAuthRepository } from '../repositories/user-auth.repository'
import { TypeOfVerificationCode } from '../auth.constants'
import { SetNewPasswordDto } from '../dtos/password.dto'
import { SLTService } from '../../../shared/services/slt.service'
import {
  HASHING_SERVICE,
  SLT_SERVICE,
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  USER_AGENT_SERVICE,
  SESSIONS_SERVICE
} from 'src/shared/constants/injection.tokens'
import { HashingService } from '../../../shared/services/hashing.service'
import { SessionsService } from './session.service'
import { EmailService } from '../../../shared/services/email.service'
import { I18nService } from 'nestjs-i18n'
import { GeolocationService } from '../../../shared/services/geolocation.service'
import { UserAgentService } from '../../../shared/services/user-agent.service'

@Injectable()
export class PasswordService {
  private readonly logger = new Logger(PasswordService.name)

  constructor(
    private readonly userAuthRepository: UserAuthRepository,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    @Inject(SESSIONS_SERVICE) private readonly sessionsService: SessionsService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly i18nService: I18nService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService
  ) {}

  async initiatePasswordReset(email: string, ipAddress: string, userAgent: string, res: Response) {
    this.logger.log(`[initiatePasswordReset] Password reset initiated for email: ${email}`)
    const user = await this.userAuthRepository.findByEmail(email)
    if (!user) {
      this.logger.warn(`[initiatePasswordReset] Email not found: ${email}.`)
      // Still return a success-like response to prevent email enumeration
      return { message: this.i18nService.t('auth.Auth.Password.ResetEmailSent') }
    }

    return this.authVerificationService.initiateVerification(
      {
        userId: user.id,
        deviceId: 0, // No device context for logged-out reset
        email: user.email,
        ipAddress,
        userAgent,
        purpose: TypeOfVerificationCode.RESET_PASSWORD
      },
      res
    )
  }

  async setNewPassword(
    sltCookieValue: string,
    dto: SetNewPasswordDto,
    ipAddress: string,
    userAgent: string,
    res: Response
  ) {
    this.logger.log(`[setNewPassword] Attempting to set new password.`)
    const { newPassword, revokeAllSessions } = dto

    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(
      sltCookieValue,
      ipAddress,
      userAgent,
      TypeOfVerificationCode.RESET_PASSWORD
    )

    if (sltContext.metadata?.otpVerified !== 'true') {
      throw AuthError.VerificationFailed({
        message: 'OTP for password reset has not been verified.'
      })
    }

    const { userId } = sltContext
    const user = await this.userAuthRepository.findById(userId, { email: true, userProfile: true })
    if (!user) {
      throw AuthError.EmailNotFound()
    }

    const hashedPassword = await this.hashingService.hash(newPassword)
    await this.userAuthRepository.updatePassword(userId, hashedPassword)

    if (revokeAllSessions) {
      await this.sessionsService.invalidateAllUserSessions(userId)
    }

    const locationResult = await this.geolocationService.getLocationFromIP(ipAddress)
    const uaInfo = this.userAgentService.parse(userAgent)

    const details = [
      {
        label: this.i18nService.t('email.Email.common.details.time'),
        value: new Date().toLocaleString('vi-VN', {
          timeZone: locationResult.timezone || 'Asia/Ho_Chi_Minh',
          dateStyle: 'full',
          timeStyle: 'long'
        })
      },
      { label: this.i18nService.t('email.Email.common.details.ipAddress'), value: ipAddress },
      { label: this.i18nService.t('email.Email.common.details.device'), value: `${uaInfo.browser} on ${uaInfo.os}` }
    ]

    await this.emailService.sendPasswordChangedEmail(user.email, {
      userName: user.userProfile?.username ?? user.email,
      details
    })

    this.sltService.finalizeSlt(sltContext.sltJti)
    // No need to clear cookie here, `finalizeSlt` handles the context.
    // The response will not include a Set-Cookie header to clear it, which is fine.

    return { message: this.i18nService.t('auth.Auth.Password.ResetSuccess') }
  }
}
