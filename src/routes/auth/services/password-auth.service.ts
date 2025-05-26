import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { ResetPasswordBodyType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCode, TokenType } from '../constants/auth.constants'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { EmailNotFoundException, InvalidPasswordException, InvalidOTPTokenException } from 'src/routes/auth/auth.error'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { Prisma } from '@prisma/client'
import { I18nContext } from 'nestjs-i18n'
import envConfig from 'src/shared/config'
import { Response } from 'express'

@Injectable()
export class PasswordAuthService extends BaseAuthService {
  private readonly logger = new Logger(PasswordAuthService.name)

  async resetPassword(
    body: ResetPasswordBodyType & { userAgent?: string; ip?: string; sltCookie?: string },
    res: Response
  ) {
    const { newPassword, userAgent, ip, sltCookie } = body
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'PASSWORD_RESET_ATTEMPT_WITH_SLT',
      ipAddress: ip,
      userAgent: userAgent,
      status: AuditLogStatus.FAILURE,
      details: { sltCookieProvided: !!sltCookie }
    }

    if (!sltCookie) {
      auditLogEntry.errorMessage = 'Missing SLT cookie for password reset.'
      auditLogEntry.details.reason = 'MISSING_SLT_COOKIE_RESET_PWD'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Session.InvalidLogin')
    }

    try {
      const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
        sltCookie,
        ip!,
        userAgent!,
        TypeOfVerificationCode.RESET_PASSWORD
      )

      auditLogEntry.userId = sltContext.userId
      auditLogEntry.userEmail = sltContext.email
      auditLogEntry.details.sltJti = sltContext.sltJti
      auditLogEntry.details.sltPurpose = sltContext.purpose

      if (!sltContext.userId) {
        auditLogEntry.errorMessage = 'User ID missing in SLT context for password reset.'
        auditLogEntry.details.reason = 'USER_ID_MISSING_IN_SLT_RESET_PWD'
        await this.otpService.finalizeSlt(sltContext.sltJti)
        this.tokenService.clearSltCookie(res)
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }

      if (!sltContext.metadata?.otpVerified || sltContext.metadata.otpVerified !== '1') {
        auditLogEntry.errorMessage = 'OTP not verified for password reset via SLT context.'
        auditLogEntry.details.reason = 'OTP_NOT_VERIFIED_IN_SLT_RESET_PWD'
        throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Otp.NotVerified')
      }

      const user = await this.sharedUserRepository.findUnique({ id: sltContext.userId })
      if (!user) {
        auditLogEntry.errorMessage = `User not found (ID: ${sltContext.userId}) for password reset.`
        auditLogEntry.details.reason = 'USER_NOT_FOUND_RESET_PWD'
        await this.otpService.finalizeSlt(sltContext.sltJti)
        this.tokenService.clearSltCookie(res)
        throw EmailNotFoundException
      }

      const hashedPassword = await this.hashingService.hash(newPassword)
      await this.authRepository.updateUser({ id: user.id }, { password: hashedPassword })

      await this.otpService.finalizeSlt(sltContext.sltJti)
      this.tokenService.clearSltCookie(res)

      await this.tokenService.invalidateAllUserSessions(user.id, 'PASSWORD_RESET')

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'PASSWORD_RESET_SUCCESS_WITH_SLT'
      auditLogEntry.details.allSessionsInvalidated = true
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      try {
        const lang = this.i18nService.resolveLanguage(user.email)
        await this.emailService.sendSecurityAlertEmail({
          to: user.email,
          userName: user.name,
          alertSubject: this.i18nService.translate('email.Email.SecurityAlert.Subject.PasswordReset', { lang }),
          alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.PasswordReset', { lang }),
          mainMessage: this.i18nService.translate('email.Email.SecurityAlert.MainMessage.PasswordReset', { lang }),
          actionDetails: [
            {
              label: this.i18nService.translate('email.Email.Field.Time', { lang }),
              value: new Date().toLocaleString(lang)
            },
            { label: this.i18nService.translate('email.Email.Field.IPAddress', { lang }), value: ip || 'N/A' }
          ],
          secondaryMessage: this.i18nService.translate('email.Email.SecurityAlert.SecondaryMessage.Password.NotYou', {
            lang
          }),
          actionButtonText: this.i18nService.translate('email.Email.SecurityAlert.Button.SecureAccount', { lang }),
          actionButtonUrl: `${envConfig.FRONTEND_HOST_URL}/account/security`
        })
      } catch (emailError) {
        this.logger.error(`Failed to send password reset security alert to ${user.email}: ${emailError.message}`)
      }

      const message = await this.i18nService.translate('error.Auth.Password.ResetSuccess', {
        lang: this.i18nService.resolveLanguage(user.email)
      })
      return { message }
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage =
          error instanceof Error ? error.message : 'Unknown error during password reset with SLT'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      if (sltCookie && (!auditLogEntry.status || auditLogEntry.status === AuditLogStatus.FAILURE)) {
        try {
          const sltContextForCleanup = await this.otpService.validateSltFromCookieAndGetContext(
            sltCookie,
            ip!,
            userAgent!
          )
          if (sltContextForCleanup && sltContextForCleanup.sltJti) {
            await this.otpService.finalizeSlt(sltContextForCleanup.sltJti)
            this.tokenService.clearSltCookie(res)
            this.logger.debug('SLT context finalized during password reset error handling.')
          }
        } catch (cleanupError) {
          this.logger.error('Error during SLT context cleanup in password reset error handler:', cleanupError)
          this.tokenService.clearSltCookie(res)
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
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
          alertSubject: this.i18nService.translate('email.Email.SecurityAlert.Subject.PasswordChanged', {
            lang: this.i18nService.resolveLanguage(user.email)
          }),
          alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.PasswordChanged', {
            lang: this.i18nService.resolveLanguage(user.email)
          }),
          mainMessage: this.i18nService.translate('email.Email.SecurityAlert.MainMessage.PasswordChanged', {
            lang: this.i18nService.resolveLanguage(user.email),
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
          actionButtonUrl: `${envConfig.FRONTEND_HOST_URL}/login` // Or account security page
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
