import { Injectable, Logger } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { ResetPasswordBodyType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCode } from '../constants/auth.constants'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { EmailNotFoundException, InvalidPasswordException, InvalidOTPTokenException } from 'src/routes/auth/auth.error'
import { Prisma } from '@prisma/client'
import { I18nContext } from 'nestjs-i18n'
import envConfig from 'src/shared/config'

@Injectable()
export class PasswordAuthService extends BaseAuthService {
  private readonly logger = new Logger(PasswordAuthService.name)

  async resetPassword(body: ResetPasswordBodyType & { userAgent?: string; ip?: string }) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'PASSWORD_RESET_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: { email: body.email, type: TypeOfVerificationCode.RESET_PASSWORD } as Prisma.JsonObject
    }

    try {
      const verificationPayload = await this.otpService.validateVerificationToken(
        body.otpToken,
        TypeOfVerificationCode.RESET_PASSWORD,
        body.email
      )

      if (!verificationPayload.userId) {
        auditLogEntry.errorMessage = 'User ID missing in OTP token payload for password reset.'
        auditLogEntry.details.reason = 'MISSING_USER_ID_IN_OTP_TOKEN'
        throw InvalidOTPTokenException
      }

      const user = await this.sharedUserRepository.findUnique({ id: verificationPayload.userId })
      if (!user) {
        auditLogEntry.errorMessage = `User with ID ${verificationPayload.userId} not found during password reset.`
        auditLogEntry.details.reason = 'USER_NOT_FOUND'
        throw EmailNotFoundException
      }

      const hashedPassword = await this.hashingService.hash(body.newPassword)

      await this.prismaService.$transaction(async (tx) => {
        await this.authRepository.updateUser({ id: user.id }, { password: hashedPassword }, tx)

        const now = Math.floor(Date.now() / 1000)
        await this.otpService.blacklistVerificationToken(verificationPayload.jti, now, verificationPayload.exp, tx)

        await this.tokenService.invalidateAllUserSessions(user.id, 'PASSWORD_RESET_SUCCESS')
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.userId = user.id
      auditLogEntry.action = 'PASSWORD_RESET_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      try {
        await this.emailService.sendSecurityAlertEmail({
          to: user.email,
          userName: user.name,
          alertSubject: await this.i18nService.translate('email.Email.SecurityAlert.Subject.PasswordReset', {
            lang: I18nContext.current()?.lang
          }),
          alertTitle: await this.i18nService.translate('email.Email.SecurityAlert.Title.PasswordReset', {
            lang: I18nContext.current()?.lang
          }),
          mainMessage: await this.i18nService.translate('email.Email.SecurityAlert.MainMessage.PasswordReset', {
            lang: I18nContext.current()?.lang,
            args: { userName: user.name }
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
        this.logger.error(`Failed to send password reset notification email to ${user.email}: ${emailError.message}`)
      }

      const message = await this.i18nService.translate('Auth.Password.ResetSuccess', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      auditLogEntry.errorMessage = error instanceof Error ? error.message : String(error)
      if (error instanceof ApiException && error.details) {
        auditLogEntry.details.originalError = error.details as unknown as Prisma.JsonObject[]
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      this.logger.error(`Password reset failed for ${body.email}: ${error.message}`, error.stack)
      throw error
    }
  }

  async changePassword(userId: number, currentPassword: string, newPassword: string, ip?: string, userAgent?: string) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'PASSWORD_CHANGE_ATTEMPT',
      userId,
      ipAddress: ip,
      userAgent,
      status: AuditLogStatus.FAILURE,
      details: { userId } as Prisma.JsonObject
    }
    try {
      const user = await this.sharedUserRepository.findUniqueWithRole({ id: userId })
      if (!user) {
        auditLogEntry.errorMessage = 'User not found.'
        auditLogEntry.details.reason = 'USER_NOT_FOUND'
        throw EmailNotFoundException
      }
      auditLogEntry.userEmail = user.email

      const isPasswordValid = await this.hashingService.compare(currentPassword, user.password)
      if (!isPasswordValid) {
        auditLogEntry.errorMessage = 'Invalid current password.'
        auditLogEntry.details.reason = 'INVALID_CURRENT_PASSWORD'
        throw InvalidPasswordException
      }

      const newHashedPassword = await this.hashingService.hash(newPassword)
      await this.authRepository.updateUser({ id: userId }, { password: newHashedPassword })

      await this.tokenService.invalidateAllUserSessions(userId, 'PASSWORD_CHANGE_SUCCESS')
      auditLogEntry.details.allSessionsInvalidated = true

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'PASSWORD_CHANGE_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      try {
        await this.emailService.sendSecurityAlertEmail({
          to: user.email,
          userName: user.name,
          alertSubject: await this.i18nService.translate('email.Email.SecurityAlert.Subject.PasswordChanged', {
            lang: I18nContext.current()?.lang
          }),
          alertTitle: await this.i18nService.translate('email.Email.SecurityAlert.Title.PasswordChanged', {
            lang: I18nContext.current()?.lang
          }),
          mainMessage: await this.i18nService.translate('email.Email.SecurityAlert.MainMessage.PasswordChanged', {
            lang: I18nContext.current()?.lang,
            args: { userName: user.name }
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
        this.logger.error(`Failed to send password change notification email to ${user.email}: ${emailError.message}`)
      }

      const message = await this.i18nService.translate('Auth.Password.ChangeSuccess', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      auditLogEntry.errorMessage = error instanceof Error ? error.message : String(error)
      if (error instanceof ApiException && error.details) {
        auditLogEntry.details.originalError = error.details as unknown as Prisma.JsonObject[]
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      this.logger.error(`Password change failed for user ${userId}: ${error.message}`, error.stack)
      throw error
    }
  }
}
