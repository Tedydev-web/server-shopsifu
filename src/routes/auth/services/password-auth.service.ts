import { Injectable, Logger } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { ResetPasswordBodyType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCode, TokenType } from '../constants/auth.constants'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { EmailNotFoundException } from 'src/routes/auth/auth.error'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { Prisma } from '@prisma/client'
import { I18nContext } from 'nestjs-i18n'
import envConfig from 'src/shared/config'

@Injectable()
export class PasswordAuthService extends BaseAuthService {
  private readonly logger = new Logger(PasswordAuthService.name)

  async resetPassword(body: ResetPasswordBodyType & { userAgent?: string; ip?: string }) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'RESET_PASSWORD_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: { otpTokenProvided: !!body.otpToken } as Prisma.JsonObject
    }

    try {
      await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        const verificationToken = await this.otpService.validateVerificationToken({
          token: body.otpToken,
          email: body.email,
          type: TypeOfVerificationCode.RESET_PASSWORD,
          tokenType: TokenType.OTP,
          tx
        })

        if (verificationToken.userId) {
          auditLogEntry.userId = verificationToken.userId
        }

        const user = await tx.user.findUnique({ where: { email: body.email } })
        if (!user) {
          throw EmailNotFoundException
        }

        auditLogEntry.userId = user.id

        const hashedPassword = await this.hashingService.hash(body.newPassword)

        await this.authRepository.updateUser({ id: user.id }, { password: hashedPassword }, tx)

        // Invalidate all sessions for this user
        await this.tokenService.invalidateAllUserSessions(user.id, 'PASSWORD_RESET')

        await this.otpService.deleteOtpToken(body.otpToken, tx)

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'RESET_PASSWORD_SUCCESS'
        if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
          ;(auditLogEntry.details as Prisma.JsonObject).refreshTokensRevoked = true
        }
      })

      // Send security alert email
      const userForEmail = await this.sharedUserRepository.findUnique({ email: body.email })
      if (userForEmail) {
        const lang = I18nContext.current()?.lang || 'en'
        let locationInfo = body.ip || 'N/A'
        let auditLocationInfo = 'N/A'
        if (body.ip) {
          const geoLocation = this.geolocationService.lookup(body.ip)
          if (geoLocation) {
            locationInfo = `${geoLocation.city || 'Unknown'}, ${geoLocation.country || 'N/A'}`
            auditLocationInfo = locationInfo
            if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
              ;(auditLogEntry.details as Prisma.JsonObject).location = auditLocationInfo
            }
          }
        }

        try {
          await this.emailService.sendSecurityAlertEmail({
            to: userForEmail.email,
            userName: userForEmail.name,
            alertSubject: this.i18nService.translate('email.Email.SecurityAlert.Subject.PasswordReset', {
              lang
            }),
            alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.PasswordReset', { lang }),
            mainMessage: this.i18nService.translate('email.Email.SecurityAlert.MainMessage.PasswordReset', {
              lang
            }),
            actionDetails: [
              {
                label: this.i18nService.translate('email.Email.Field.Time', { lang }),
                value: new Date().toLocaleString(lang)
              },
              {
                label: this.i18nService.translate('email.Email.Field.IPAddress', { lang }),
                value: body.ip || 'N/A'
              },
              {
                label: this.i18nService.translate('email.Email.Field.Device', { lang }),
                value: body.userAgent || 'N/A'
              },
              {
                label: this.i18nService.translate('email.Email.Field.Location', { lang }),
                value: locationInfo
              }
            ],
            secondaryMessage: this.i18nService.translate('email.Email.SecurityAlert.SecondaryMessage.Password.NotYou', {
              lang
            }),
            actionButtonText: this.i18nService.translate('email.Email.SecurityAlert.Button.SecureAccount', {
              lang
            }),
            actionButtonUrl: `${envConfig.FRONTEND_HOST_URL}/account/security`
          })
        } catch (emailError) {
          this.logger.error(
            `Failed to send password reset security alert to ${userForEmail.email}: ${emailError.message}`,
            emailError.stack
          )
        }
      }

      await this.auditLogService.record(auditLogEntry as AuditLogData)
      const message = await this.i18nService.translate('error.Auth.Password.ResetSuccess', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async changePassword(userId: number, currentPassword: string, newPassword: string, ip?: string, userAgent?: string) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'CHANGE_PASSWORD_ATTEMPT',
      userId,
      ipAddress: ip,
      userAgent,
      status: AuditLogStatus.FAILURE,
      details: {} as Prisma.JsonObject
    }

    try {
      await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        const user = await tx.user.findUnique({ where: { id: userId } })
        if (!user) {
          throw new ApiException(404, 'User not found', 'Auth.UserNotFound')
        }

        const isPasswordMatch = await this.hashingService.compare(currentPassword, user.password)
        if (!isPasswordMatch) {
          throw new ApiException(400, 'Current password is incorrect', 'Auth.Password.CurrentPasswordIncorrect')
        }

        const hashedNewPassword = await this.hashingService.hash(newPassword)
        await this.authRepository.updateUser({ id: userId }, { password: hashedNewPassword }, tx)

        // Invalidate all sessions for this user
        await this.tokenService.invalidateAllUserSessions(userId, 'PASSWORD_CHANGED')

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'CHANGE_PASSWORD_SUCCESS'
        if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
          ;(auditLogEntry.details as Prisma.JsonObject).refreshTokensRevoked = true
        }
      })

      // Send security alert email
      const userForEmailAfterChange = await this.sharedUserRepository.findUnique({ id: userId })
      if (userForEmailAfterChange) {
        const lang = I18nContext.current()?.lang || 'en'
        let locationInfo = ip || 'N/A'
        let auditLocationInfo = 'N/A'
        if (ip) {
          const geoLocation = this.geolocationService.lookup(ip)
          if (geoLocation) {
            locationInfo = `${geoLocation.city || 'Unknown'}, ${geoLocation.country || 'N/A'}`
            auditLocationInfo = locationInfo
            if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
              ;(auditLogEntry.details as Prisma.JsonObject).location = auditLocationInfo
            }
          }
        }

        try {
          await this.emailService.sendSecurityAlertEmail({
            to: userForEmailAfterChange.email,
            userName: userForEmailAfterChange.name,
            alertSubject: this.i18nService.translate('email.Email.SecurityAlert.Subject.PasswordChanged', {
              lang
            }),
            alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.PasswordChanged', {
              lang
            }),
            mainMessage: this.i18nService.translate('email.Email.SecurityAlert.MainMessage.PasswordChanged', {
              lang
            }),
            actionDetails: [
              {
                label: this.i18nService.translate('email.Email.Field.Time', { lang }),
                value: new Date().toLocaleString(lang)
              },
              {
                label: this.i18nService.translate('email.Email.Field.IPAddress', { lang }),
                value: ip || 'N/A'
              },
              {
                label: this.i18nService.translate('email.Email.Field.Device', { lang }),
                value: userAgent || 'N/A'
              },
              {
                label: this.i18nService.translate('email.Email.Field.Location', { lang }),
                value: locationInfo
              }
            ],
            secondaryMessage: this.i18nService.translate('email.Email.SecurityAlert.SecondaryMessage.Password.NotYou', {
              lang
            }),
            actionButtonText: this.i18nService.translate('email.Email.SecurityAlert.Button.SecureAccount', {
              lang
            }),
            actionButtonUrl: `${envConfig.FRONTEND_HOST_URL}/account/security`
          })
        } catch (emailError) {
          this.logger.error(
            `Failed to send password change security alert to ${userForEmailAfterChange.email}: ${emailError.message}`,
            emailError.stack
          )
        }
      }

      await this.auditLogService.record(auditLogEntry as AuditLogData)
      const message = await this.i18nService.translate('error.Auth.Password.ChangeSuccess', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
