import { Injectable } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { v4 as uuidv4 } from 'uuid'
import { TokenType, TwoFactorMethodType, TypeOfVerificationCode } from '../constants/auth.constants'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { DisableTwoFactorBodyType, TwoFactorVerifyBodyType } from 'src/routes/auth/auth.model'
import {
  DeviceMismatchException,
  InvalidTOTPException,
  TOTPAlreadyEnabledException,
  TOTPNotEnabledException
} from 'src/routes/auth/auth.error'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { Response } from 'express'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { Prisma } from '@prisma/client'

@Injectable()
export class TwoFactorAuthService extends BaseAuthService {
  async setupTwoFactorAuth(userId: number) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'SETUP_2FA_ATTEMPT',
      userId,
      status: AuditLogStatus.FAILURE,
      details: {} as Prisma.JsonObject
    }

    try {
      const user = await this.sharedUserRepository.findUnique({ id: userId })
      if (!user) {
        throw new ApiException(404, 'User not found', 'Auth.UserNotFound')
      }

      if (user.twoFactorEnabled && user.twoFactorSecret) {
        auditLogEntry.errorMessage = TOTPAlreadyEnabledException.message
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        throw TOTPAlreadyEnabledException
      }

      const { secret, uri } = this.twoFactorService.generateTOTPSecret(user.email)
      const setupToken = uuidv4()

      await this.prismaService.verificationToken.create({
        data: {
          token: setupToken,
          email: user.email,
          type: TypeOfVerificationCode.SETUP_2FA,
          tokenType: TokenType.SETUP_2FA_TOKEN,
          expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
          userId,
          metadata: JSON.stringify({ secret })
        }
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'SETUP_2FA_INITIATED'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return {
        secret,
        uri,
        setupToken
      }
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error.message
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async confirmTwoFactorSetup(userId: number, setupToken: string, totpCode: string) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'CONFIRM_2FA_SETUP_ATTEMPT',
      userId,
      status: AuditLogStatus.FAILURE,
      details: {} as Prisma.JsonObject
    }

    try {
      const setupVerification = await this.prismaService.verificationToken.findFirst({
        where: {
          token: setupToken,
          userId,
          type: TypeOfVerificationCode.SETUP_2FA,
          tokenType: TokenType.SETUP_2FA_TOKEN,
          expiresAt: { gt: new Date() }
        }
      })

      if (!setupVerification || !setupVerification.metadata) {
        throw new ApiException(400, 'Invalid or expired setup token', 'Auth.TwoFactor.InvalidSetupToken')
      }

      let secret: string
      try {
        const metadata = JSON.parse(setupVerification.metadata)
        secret = metadata.secret
        if (!secret) {
          throw new Error('Secret not found in token metadata')
        }
      } catch {
        throw new ApiException(400, 'Invalid setup token metadata', 'Auth.TwoFactor.InvalidSetupToken')
      }

      const isValid = this.twoFactorService.verifyTOTP({
        email: userId.toString(),
        secret,
        token: totpCode
      })

      if (!isValid) {
        auditLogEntry.errorMessage = InvalidTOTPException.message
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        throw InvalidTOTPException
      }

      const recoveryCodes = this.twoFactorService.generateRecoveryCodes()

      // Update user with 2FA settings
      await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        await tx.user.update({
          where: { id: userId },
          data: {
            twoFactorEnabled: true,
            twoFactorSecret: secret,
            twoFactorMethod: TwoFactorMethodType.TOTP
          }
        })

        // Save recovery codes
        await this.twoFactorService.saveRecoveryCodes(userId, recoveryCodes, tx)

        // Delete the setup token
        await tx.verificationToken.delete({
          where: { id: setupVerification.id }
        })
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'CONFIRM_2FA_SETUP_SUCCESS'
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        ;(auditLogEntry.details as Prisma.JsonObject).recoveryCodesGenerated = recoveryCodes.length
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return {
        message: 'Two-factor authentication has been enabled.',
        recoveryCodes
      }
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error.message
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async disableTwoFactorAuth(data: DisableTwoFactorBodyType & { userId: number; userAgent?: string; ip?: string }) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'DISABLE_2FA_ATTEMPT',
      userId: data.userId,
      ipAddress: data.ip,
      userAgent: data.userAgent,
      status: AuditLogStatus.FAILURE,
      details: { type: data.type } as Prisma.JsonObject
    }

    try {
      const user = await this.sharedUserRepository.findUnique({ id: data.userId })
      if (!user) {
        throw new ApiException(404, 'User not found', 'Auth.UserNotFound')
      }

      if (!user.twoFactorEnabled || !user.twoFactorSecret) {
        auditLogEntry.errorMessage = TOTPNotEnabledException.message
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        throw TOTPNotEnabledException
      }

      let isValid = false
      if (data.type === TwoFactorMethodType.TOTP) {
        isValid = this.twoFactorService.verifyTOTP({
          email: user.email,
          secret: user.twoFactorSecret,
          token: data.code
        })
      } else if (data.type === TwoFactorMethodType.RECOVERY && data.code) {
        try {
          await this.twoFactorService.verifyRecoveryCode(data.userId, data.code)
          isValid = true
        } catch {
          isValid = false
        }
      }

      if (!isValid) {
        auditLogEntry.errorMessage = InvalidTOTPException.message
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        throw InvalidTOTPException
      }

      await this.twoFactorService.updateUserTwoFactorStatus(data.userId, {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorMethod: null
      })

      await this.twoFactorService.deleteAllRecoveryCodes(data.userId)

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'DISABLE_2FA_SUCCESS'
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        ;(auditLogEntry.details as Prisma.JsonObject).verificationMethod = data.type
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return { message: 'Two-factor authentication has been disabled successfully.' }
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error.message
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async verifyTwoFactor(body: TwoFactorVerifyBodyType & { userAgent: string; ip: string }, res?: Response) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'VERIFY_2FA_ATTEMPT',
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        type: body.type,
        loginSessionTokenProvided: !!body.loginSessionToken
      } as Prisma.JsonObject
    }

    try {
      const result = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        const sessionToken = await this.otpService.findVerificationToken(body.loginSessionToken, tx)
        if (!sessionToken || !sessionToken.userId || !sessionToken.deviceId) {
          throw new ApiException(400, 'Invalid login session token', 'Auth.TwoFactor.InvalidLoginSessionToken')
        }

        auditLogEntry.userId = sessionToken.userId
        auditLogEntry.userEmail = sessionToken.email
        if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
          ;(auditLogEntry.details as Prisma.JsonObject).deviceId = sessionToken.deviceId
        }

        const user = await tx.user.findUnique({
          where: { id: sessionToken.userId },
          include: { role: true }
        })

        if (!user) {
          throw new ApiException(404, 'User not found', 'Auth.UserNotFound')
        }

        const isLoginFor2FA = sessionToken.type === TypeOfVerificationCode.LOGIN_2FA
        const isLoginForUntrustedDevice = sessionToken.type === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP

        // Validate based on verification type
        if (isLoginFor2FA && user.twoFactorEnabled && user.twoFactorSecret) {
          let isValid = false

          if (body.type === TwoFactorMethodType.TOTP) {
            isValid = this.twoFactorService.verifyTOTP({
              email: user.email,
              secret: user.twoFactorSecret,
              token: body.code
            })
          } else if (body.type === TwoFactorMethodType.RECOVERY && body.code) {
            try {
              await this.twoFactorService.verifyRecoveryCode(user.id, body.code, tx)
              isValid = true
            } catch {
              isValid = false
            }
          }

          if (!isValid) {
            auditLogEntry.errorMessage = InvalidTOTPException.message
            throw InvalidTOTPException
          }
        } else if (isLoginForUntrustedDevice && body.type === TwoFactorMethodType.OTP) {
          await this.otpService.validateVerificationCode({
            email: user.email,
            code: body.code,
            type: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
            tx
          })
        } else {
          throw new ApiException(400, 'Invalid verification method', 'Auth.TwoFactor.InvalidVerificationMethod')
        }

        // Check if device is valid
        const device = await tx.device.findUnique({
          where: { id: sessionToken.deviceId }
        })

        if (!device || device.userId !== user.id) {
          auditLogEntry.errorMessage = DeviceMismatchException.message
          throw DeviceMismatchException
        }

        // Extract rememberMe from session token metadata
        let rememberMe = false
        if (sessionToken.metadata) {
          try {
            const metadata = JSON.parse(sessionToken.metadata)
            rememberMe = !!metadata.rememberMe
          } catch (error) {
            this.logger.warn('Could not parse metadata for rememberMe preference', error)
          }
        }

        // Generate tokens
        const { accessToken, refreshToken, maxAgeForRefreshTokenCookie } = await this.tokenService.generateTokens(
          {
            userId: user.id,
            deviceId: device.id,
            roleId: user.roleId,
            roleName: user.role.name
          },
          tx,
          rememberMe
        )

        // Delete the session token
        await this.otpService.deleteOtpToken(body.loginSessionToken, tx)

        if (res) {
          this.tokenService.setTokenCookies(res, accessToken, refreshToken, maxAgeForRefreshTokenCookie)
        }

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'VERIFY_2FA_SUCCESS'
        if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
          ;(auditLogEntry.details as Prisma.JsonObject).verificationMethod = body.type
          ;(auditLogEntry.details as Prisma.JsonObject).rememberMe = rememberMe
        }

        return {
          userId: user.id,
          email: user.email,
          name: user.name,
          role: user.role.name
        }
      })

      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error.message
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
