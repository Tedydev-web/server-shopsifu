import { Injectable, Logger, HttpStatus } from '@nestjs/common'
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

  async resetPassword(body: ResetPasswordBodyType & { userAgent?: string; ip?: string; sltCookieValue?: string }) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'PASSWORD_RESET_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        email: body.email,
        type: TypeOfVerificationCode.RESET_PASSWORD,
        sltCookieProvided: !!body.sltCookieValue
      } as Prisma.JsonObject
    }

    if (!body.sltCookieValue) {
      auditLogEntry.errorMessage = 'SLT cookie is missing for password reset.'
      auditLogEntry.details.reason = 'MISSING_SLT_COOKIE_RESET_PASSWORD'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
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
      auditLogEntry.details.sltJti = sltContext.sltJti
      auditLogEntry.details.sltPurpose = sltContext.purpose
      auditLogEntry.userEmail = sltContext.email

      if (body.email && sltContext.email !== body.email) {
        auditLogEntry.errorMessage = 'Email mismatch between SLT context and reset password body.'
        auditLogEntry.details.reason = 'EMAIL_MISMATCH_SLT_RESET_PASSWORD'
        throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Email.Mismatch')
      }

      if (
        !sltContext.metadata?.otpVerified ||
        sltContext.metadata?.stageVerified !== TypeOfVerificationCode.RESET_PASSWORD
      ) {
        auditLogEntry.errorMessage = 'OTP not verified for password reset via SLT context.'
        auditLogEntry.details.reason = 'SLT_OTP_NOT_VERIFIED_FOR_RESET_PASSWORD'
        auditLogEntry.details.sltMetadata = sltContext.metadata as Prisma.JsonObject | undefined
        throw new ApiException(HttpStatus.BAD_REQUEST, 'OtpVerificationRequired', 'Error.Auth.Otp.VerificationRequired')
      }
      auditLogEntry.details.sltOtpStageVerified = true

      if (!sltContext.userId) {
        auditLogEntry.errorMessage = 'User ID missing in SLT context payload for password reset.'
        auditLogEntry.details.reason = 'MISSING_USER_ID_IN_SLT_CONTEXT'
        throw new InvalidOTPTokenException()
      }
      auditLogEntry.userId = sltContext.userId

      const user = await this.userRepository.findUniqueWithDetails({ id: sltContext.userId })
      if (!user) {
        auditLogEntry.errorMessage = `User with ID ${sltContext.userId} not found during password reset (from SLT).`
        auditLogEntry.details.reason = 'USER_NOT_FOUND_FROM_SLT'
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
      auditLogEntry.details.finalizedSltJtiOnSuccess = sltContext.sltJti

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'PASSWORD_RESET_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

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
      this.logger.error(
        `Password reset failed for ${auditLogEntry.userEmail || 'unknown user'}: ${error.message}`,
        error.stack
      )

      if (sltJtiForFinalizeOnError && !auditLogEntry.details.finalizedSltJtiOnSuccess) {
        if (error instanceof ApiException && error.getStatus() === (HttpStatus.BAD_REQUEST as number)) {
          await this.otpService.finalizeSlt(sltJtiForFinalizeOnError)
          auditLogEntry.details.finalizedSltJtiOnError = sltJtiForFinalizeOnError
          this.logger.warn(`SLT ${sltJtiForFinalizeOnError} finalized due to error: ${error.message}`)
        }
      }
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
      const user = await this.userRepository.findUniqueWithDetails({ id: userId })
      if (!user) {
        auditLogEntry.errorMessage = 'User not found.'
        auditLogEntry.details.reason = 'USER_NOT_FOUND'
        throw new EmailNotFoundException()
      }
      auditLogEntry.userEmail = user.email

      const isPasswordValid = await this.hashingService.compare(currentPassword, user.password)
      if (!isPasswordValid) {
        auditLogEntry.errorMessage = 'Invalid current password.'
        auditLogEntry.details.reason = 'INVALID_CURRENT_PASSWORD'
        throw new InvalidPasswordException()
      }

      const newHashedPassword = await this.hashingService.hash(newPassword)
      await this.userRepository.updateUser(
        { id: userId },
        { password: newHashedPassword, passwordChangedAt: new Date() }
      )

      await this.tokenService.invalidateAllUserSessions(userId, 'PASSWORD_CHANGE_SUCCESS')
      auditLogEntry.details.allSessionsInvalidated = true

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'PASSWORD_CHANGE_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

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
