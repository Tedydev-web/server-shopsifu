import { Injectable } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { SendOTPBodyType, VerifyCodeBodyType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCode } from '../constants/auth.constants'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { EmailAlreadyExistsException, EmailNotFoundException } from 'src/routes/auth/auth.error'
import { DeviceSetupFailedException } from '../auth.error'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { Prisma } from '@prisma/client'
import { I18nContext } from 'nestjs-i18n'
import envConfig from 'src/shared/config'

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

        // Lookup geolocation
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

        const token = await this.otpService.createOtpToken({
          email: body.email,
          type: body.type,
          userId,
          deviceId,
          metadata: {
            // Include other necessary metadata from AuthenticationService if any, for now, just geo
            ...geoLocationMetadata
          },
          tx
        })

        await this.otpService.deleteVerificationCode(body.email, body.code, body.type, tx)

        // Send security alert email if this was for LOGIN_UNTRUSTED_DEVICE_OTP
        if (body.type === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP && userId) {
          const user = await tx.user.findUnique({ where: { id: userId } })
          if (user) {
            const lang = I18nContext.current()?.lang || 'en'
            const locationInfo =
              geoLocationMetadata.geoCity && geoLocationMetadata.geoCountry
                ? `${geoLocationMetadata.geoCity}, ${geoLocationMetadata.geoCountry}`
                : body.ip || 'N/A'
            try {
              await this.emailService.sendSecurityAlertEmail({
                to: user.email,
                userName: user.name,
                alertSubject: this.i18nService.translate('email.Email.SecurityAlert.Subject.NewDeviceLogin', { lang }),
                alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.NewDeviceLogin', { lang }),
                mainMessage: this.i18nService.translate('email.Email.SecurityAlert.MainMessage.NewDeviceLogin', {
                  lang
                }),
                actionDetails: [
                  {
                    label: this.i18nService.translate('email.Email.Field.Time', { lang }),
                    value: new Date().toLocaleString(lang)
                  },
                  { label: this.i18nService.translate('email.Email.Field.IPAddress', { lang }), value: body.ip },
                  {
                    label: this.i18nService.translate('email.Email.Field.Device', { lang }),
                    value: body.userAgent
                  },
                  {
                    label: this.i18nService.translate('email.Email.Field.Location', { lang }),
                    value: locationInfo
                  }
                ],
                secondaryMessage: this.i18nService.translate('email.Email.SecurityAlert.SecondaryMessage.NotYou', {
                  lang
                }),
                actionButtonText: this.i18nService.translate('email.Email.SecurityAlert.Button.SecureAccount', {
                  lang
                }),
                actionButtonUrl: `${envConfig.FRONTEND_HOST_URL}/account/security` // TODO: Update with actual URL
              })
            } catch (emailError) {
              this.logger.error(
                `Failed to send new device login (OTP) security alert to ${user.email}: ${emailError.message}`,
                emailError.stack
              )
              // Do not let email failure block the login flow
            }
          }
        }

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'OTP_VERIFY_SUCCESS'
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        return { otpToken: token }
      })
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
