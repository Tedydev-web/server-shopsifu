import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { ResetPasswordBodyType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCode } from '../constants/auth.constants'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { EmailNotFoundException, InvalidPasswordException, InvalidOTPTokenException } from 'src/routes/auth/auth.error'
import { Prisma } from '@prisma/client'
import { I18nContext } from 'nestjs-i18n'
import envConfig from 'src/shared/config'

@Injectable()
export class PasswordAuthService extends BaseAuthService {
  private readonly logger = new Logger(PasswordAuthService.name)

  async resetPassword(body: ResetPasswordBodyType & { userAgent?: string; ip?: string; sltCookieValue?: string }) {
    if (!body.sltCookieValue) {
      throw new ApiException(HttpStatus.BAD_REQUEST, 'SltTokenMissing', 'Error.Auth.Session.InvalidLogin')
    }

    let sltJtiForFinalizeOnError: string | undefined

    try {
      const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
        body.sltCookieValue,
        body.ip!,
        body.userAgent!,
        TypeOfVerificationCode.RESET_PASSWORD
      )
      sltJtiForFinalizeOnError = sltContext.sltJti

      if (body.email && sltContext.email !== body.email) {
        throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Email.Mismatch')
      }

      if (
        !sltContext.metadata?.otpVerified ||
        sltContext.metadata?.stageVerified !== TypeOfVerificationCode.RESET_PASSWORD
      ) {
        throw new ApiException(HttpStatus.BAD_REQUEST, 'OtpVerificationRequired', 'Error.Auth.Otp.VerificationRequired')
      }

      if (!sltContext.userId) {
        throw new InvalidOTPTokenException()
      }

      const user = await this.userRepository.findUniqueWithDetails({ id: sltContext.userId })
      if (!user) {
        throw new EmailNotFoundException()
      }

      const hashedPassword = await this.hashingService.hash(body.newPassword)

      await this.prismaService.$transaction(async (tx) => {
        await this.userRepository.updateUser(
          { id: user.id },
          { password: hashedPassword, passwordChangedAt: new Date() },
          tx
        )
        await this.tokenService.invalidateAllUserSessions(user.id, 'PASSWORD_RESET_SUCCESS')
      })

      await this.otpService.finalizeSlt(sltContext.sltJti)

      try {
        const displayName = user.userProfile?.firstName || user.userProfile?.lastName || user.email
        await this.emailService.sendSecurityAlertEmail({
          to: user.email,
          userName: displayName,
          alertSubject: await this.i18nService.translate('email.Email.SecurityAlert.Subject.PasswordReset', {
            lang: I18nContext.current()?.lang
          }),
          alertTitle: await this.i18nService.translate('email.Email.SecurityAlert.Title.PasswordReset', {
            lang: I18nContext.current()?.lang
          }),
          mainMessage: await this.i18nService.translate('email.Email.SecurityAlert.MainMessage.PasswordReset', {
            lang: I18nContext.current()?.lang,
            args: { userName: displayName }
          }),
          actionDetails: [
            { label: 'Time', value: new Date().toLocaleString() },
            { label: 'IP Address', value: body.ip || 'N/A' },
            { label: 'Device', value: body.userAgent || 'N/A' }
          ],
          secondaryMessage: await this.i18nService.translate(
            'email.Email.SecurityAlert.SecondaryMessage.Password.NotYou',
            { lang: I18nContext.current()?.lang }
          ),
          actionButtonText: await this.i18nService.translate('email.Email.SecurityAlert.Button.SecureAccount', {
            lang: I18nContext.current()?.lang
          }),
          actionButtonUrl: `${envConfig.FRONTEND_URL}/login`
        })
      } catch (emailError) {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }

      const message = await this.i18nService.translate('Auth.Password.ResetSuccess', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      if (sltJtiForFinalizeOnError) {
        if (error instanceof ApiException && error.getStatus() === (HttpStatus.BAD_REQUEST as number)) {
          await this.otpService.finalizeSlt(sltJtiForFinalizeOnError)
        }
      }
      throw error
    }
  }

  async changePassword(userId: number, currentPassword: string, newPassword: string, ip?: string, userAgent?: string) {
    try {
      const user = await this.userRepository.findUniqueWithDetails({ id: userId })
      if (!user) {
        throw new EmailNotFoundException()
      }

      const isPasswordValid = await this.hashingService.compare(currentPassword, user.password)
      if (!isPasswordValid) {
        throw new InvalidPasswordException()
      }

      const newHashedPassword = await this.hashingService.hash(newPassword)
      await this.userRepository.updateUser(
        { id: userId },
        { password: newHashedPassword, passwordChangedAt: new Date() }
      )

      await this.tokenService.invalidateAllUserSessions(userId, 'PASSWORD_CHANGE_SUCCESS')

      try {
        const displayName = user.userProfile?.firstName || user.userProfile?.lastName || user.email
        await this.emailService.sendSecurityAlertEmail({
          to: user.email,
          userName: displayName,
          alertSubject: await this.i18nService.translate('email.Email.SecurityAlert.Subject.PasswordChanged', {
            lang: I18nContext.current()?.lang
          }),
          alertTitle: await this.i18nService.translate('email.Email.SecurityAlert.Title.PasswordChanged', {
            lang: I18nContext.current()?.lang
          }),
          mainMessage: await this.i18nService.translate('email.Email.SecurityAlert.MainMessage.PasswordChanged', {
            lang: I18nContext.current()?.lang,
            args: { userName: displayName }
          }),
          actionDetails: [
            { label: 'Time', value: new Date().toLocaleString() },
            { label: 'IP Address', value: ip || 'N/A' },
            { label: 'Device', value: userAgent || 'N/A' }
          ],
          secondaryMessage: await this.i18nService.translate(
            'email.Email.SecurityAlert.SecondaryMessage.Password.NotYou',
            { lang: I18nContext.current()?.lang }
          ),
          actionButtonText: await this.i18nService.translate('email.Email.SecurityAlert.Button.SecureAccount', {
            lang: I18nContext.current()?.lang
          }),
          actionButtonUrl: `${envConfig.FRONTEND_URL}/login`
        })
      } catch (emailError) {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }

      const message = await this.i18nService.translate('Auth.Password.ChangeSuccess', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
    }
  }
}
