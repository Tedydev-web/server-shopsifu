import { Injectable, Logger } from '@nestjs/common'
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
      // Không còn $transaction ở đây vì OtpService mới xử lý Redis độc lập
      // const result = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {

      // Bước 1: Xác thực OTP và tạo Verification JWT
      const verificationJwt = await this.otpService.verifyOTPAndCreateToken({
        email: body.email,
        code: body.code,
        type: body.type,
        ip: body.ip,
        userAgent: body.userAgent
        // userId và deviceId sẽ được lấy từ payload của JWT sau này nếu cần,
        // hoặc truyền vào đây nếu đã có sẵn trước khi tạo JWT.
        // Đối với REGISTER, userId chưa có.
        // Đối với LOGIN_UNTRUSTED_DEVICE_OTP, userId có thể được tìm trước.
      })

      const existingUser = await this.sharedUserRepository.findUnique({ email: body.email })
      if (existingUser) {
        auditLogEntry.userId = existingUser.id
      }

      // deviceId có thể được thêm vào metadata của JWT nếu cần thiết và lấy từ JWT sau khi validate
      // Hoặc, nếu device đã được xác định trước khi verifyOTPAndCreateToken,
      // nó có thể được truyền vào hàm đó để đưa vào payload JWT.
      // Hiện tại, findOrCreateDevice logic ở đây sẽ không chạy trong $transaction nữa.
      // Cần xem xét lại việc tạo/tìm device nếu nó phụ thuộc vào transaction.
      // Tạm thời, bỏ qua logic device ở đây vì nó sẽ được xử lý ở bước hoàn tất login/register.

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
      // Metadata này có thể được truyền vào verifyOTPAndCreateToken nếu cần thiết trong payload JWT

      // Không cần createOtpToken và deleteVerificationCode nữa.

      // Send security alert email if this was for LOGIN_UNTRUSTED_DEVICE_OTP
      // Logic này nên được chuyển sang bước hoàn tất đăng nhập sau khi verificationJwt được xác thực thành công.
      // Tạm thời comment out để tránh lỗi và xử lý sau.
      /*
      if (body.type === TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP && existingUser) {
        const user = await this.sharedUserRepository.findUnique({ where: { id: existingUser.id } }) // Đọc lại user nếu cần thông tin mới nhất
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
      */

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'OTP_VERIFY_SUCCESS_JWT_ISSUED'
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        ;(auditLogEntry.details as Prisma.JsonObject).verificationJwtIssued = true
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return { otpToken: verificationJwt } // Trả về verification JWT
      // })
      // return result
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
