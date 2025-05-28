import { Injectable, Logger } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { SendOTPBodyType, VerifyCodeBodyType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCode } from '../constants/auth.constants'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { EmailAlreadyExistsException, EmailNotFoundException } from 'src/routes/auth/auth.error'
import { Prisma } from '@prisma/client'
import { I18nContext } from 'nestjs-i18n'

@Injectable()
export class OtpAuthService extends BaseAuthService {
  private readonly logger = new Logger(OtpAuthService.name)

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

    await this.otpService.sendOTP(body.email, body.type)
    const message = await this.i18nService.translate('error.Auth.Otp.SentSuccessfully', {
      lang: I18nContext.current()?.lang
    })
    return { message }
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
      const verificationJwt = await this.otpService.verifyOTPAndCreateToken({
        email: body.email,
        code: body.code,
        type: body.type,
        ip: body.ip,
        userAgent: body.userAgent
      })

      const existingUser = await this.sharedUserRepository.findUnique({ email: body.email })
      if (existingUser) {
        auditLogEntry.userId = existingUser.id
      }

      let geoLocationMetadata: { geoCountry?: string; geoCity?: string } = {}
      if (body.ip) {
        const geoLocation = this.geolocationService.lookup(body.ip)
        if (geoLocation) {
          geoLocationMetadata = { geoCountry: geoLocation.country, geoCity: geoLocation.city }
          if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
            ;(auditLogEntry.details as Prisma.JsonObject).location =
              `${geoLocation.city || 'N/A'}, ${geoLocation.country || 'N/A'}`
          }
        }
      }

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'OTP_VERIFY_SUCCESS_JWT_ISSUED'
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        ;(auditLogEntry.details as Prisma.JsonObject).verificationJwtIssued = true
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return { otpToken: verificationJwt }
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
