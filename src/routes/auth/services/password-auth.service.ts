import { Injectable } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { ResetPasswordBodyType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCode, TokenType } from '../constants/auth.constants'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { EmailNotFoundException } from 'src/routes/auth/auth.error'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { Prisma } from '@prisma/client'
import { I18nContext } from 'nestjs-i18n'

@Injectable()
export class PasswordAuthService extends BaseAuthService {
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
