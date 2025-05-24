import { Injectable } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { SendOTPBodyType, VerifyCodeBodyType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCode } from '../constants/auth.constants'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { EmailAlreadyExistsException, EmailNotFoundException } from 'src/routes/auth/auth.error'
import { DeviceSetupFailedException } from '../auth.error'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { Prisma } from '@prisma/client'

@Injectable()
export class OtpAuthService extends BaseAuthService {
  async sendOTP(body: SendOTPBodyType) {
    const user = await this.sharedUserRepository.findUnique({
      email: body.email
    })
    if (body.type === TypeOfVerificationCode.REGISTER && user) {
      throw EmailAlreadyExistsException
    }
    if (body.type === TypeOfVerificationCode.RESET_PASSWORD && !user) {
      throw EmailNotFoundException
    }

    return this.otpService.sendOTP(body.email, body.type)
  }

  async verifyCode(body: VerifyCodeBodyType & { userAgent: string; ip: string }) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'OTP_VERIFY_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: { type: body.type, codeProvided: !!body.code } as Prisma.JsonObject
    }
    try {
      const result = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        await this.otpService.validateVerificationCode({
          email: body.email,
          code: body.code,
          type: body.type,
          tx
        })

        const existingUser = await this.sharedUserRepository.findUnique({ email: body.email })
        if (existingUser) {
          auditLogEntry.userId = existingUser.id
        }

        let userId: number | undefined = undefined
        if (body.type !== TypeOfVerificationCode.REGISTER) {
          const userFromSharedRepo = await this.sharedUserRepository.findUnique({ email: body.email })
          if (userFromSharedRepo) {
            userId = userFromSharedRepo.id
          }
        }

        let deviceId: number | undefined = undefined
        if (userId) {
          try {
            const device = await this.deviceService.findOrCreateDevice(
              {
                userId,
                userAgent: body.userAgent,
                ip: body.ip
              },
              tx
            )
            deviceId = device.id
            if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
              ;(auditLogEntry.details as Prisma.JsonObject).deviceId = device.id
            }
          } catch (error) {
            auditLogEntry.errorMessage = DeviceSetupFailedException.message
            auditLogEntry.notes = 'Device creation/finding failed during OTP verification'
            this.logger.error('Could not create or find device in verifyCode', error)
          }
        }

        const token = await this.otpService.createOtpToken({
          email: body.email,
          type: body.type,
          userId,
          deviceId,
          tx
        })

        await this.otpService.deleteVerificationCode(body.email, body.code, body.type, tx)

        return { otpToken: token }
      })
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'OTP_VERIFY_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      if (error.getResponse) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
