import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common'
import { Response } from 'express'
import { AuthError } from '../auth.error'
import { AuthVerificationService } from './auth-verification.service'
import { TypeOfVerificationCode } from '../auth.constants'
import { SetNewPasswordDto, ChangePasswordDto } from '../dtos/password.dto'
import {
  HASHING_SERVICE,
  SLT_SERVICE,
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  USER_AGENT_SERVICE,
  SESSIONS_SERVICE,
  COOKIE_SERVICE
} from 'src/shared/constants/injection.tokens'
import { HashingService } from '../../../shared/services/hashing.service'
import { EmailService } from '../../../shared/services/email.service'
import { I18nService } from 'nestjs-i18n'
import { GeolocationService } from '../../../shared/services/geolocation.service'
import { UserAgentService } from '../../../shared/services/user-agent.service'
import { ICookieService, ISessionService, ISLTService, AccessTokenPayload } from 'src/routes/auth/auth.types'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { UserRepository } from 'src/routes/user/user.repository'
import { ActiveUserData } from 'src/shared/types/active-user.type'

@Injectable()
export class PasswordService {
  private readonly logger = new Logger(PasswordService.name)

  constructor(
    private readonly userRepository: UserRepository,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService,
    @Inject(SLT_SERVICE) private readonly sltService: ISLTService,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    @Inject(SESSIONS_SERVICE) private readonly sessionsService: ISessionService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService
  ) {}

  /**
   * Khởi tạo quá trình đặt lại mật khẩu cho người dùng đã quên.
   */
  async initiatePasswordReset(email: string, ipAddress: string, userAgent: string, res: Response) {
    this.logger.log(`Initiating password reset for email: ${email}`)
    const user = await this.userRepository.findByEmail(email)

    if (!user) {
      this.logger.warn(`Password reset initiated for non-existent email: ${email}`)
      return { message: 'auth.success.password.initiateReset' }
    }

    // Gửi đi flow xác thực
    return this.authVerificationService.initiateVerification(
      {
        userId: user.id,
        deviceId: 0, // Sẽ được tạo/cập nhật nếu cần
        email: user.email,
        ipAddress,
        userAgent,
        purpose: TypeOfVerificationCode.RESET_PASSWORD
      },
      res
    )
  }

  /**
   * Đặt mật khẩu mới sau khi người dùng xác thực thành công (luồng quên mật khẩu).
   */
  async setNewPassword(
    sltCookieValue: string,
    dto: SetNewPasswordDto,
    ipAddress: string,
    userAgent: string,
    res: Response
  ) {
    this.logger.log(`Setting new password from reset flow.`)

    const sltContext = await this.sltService.validateSltFromCookieAndGetContext(
      sltCookieValue,
      ipAddress,
      userAgent,
      TypeOfVerificationCode.RESET_PASSWORD
    )

    if (sltContext.metadata?.otpVerified !== 'true') {
      throw AuthError.InsufficientPermissions()
    }

    const result = await this.performPasswordUpdate({
      userId: sltContext.userId,
      newPassword: dto.newPassword,
      revokeAllSessions: dto.revokeAllSessions,
      ipAddress: ipAddress,
      userAgent: userAgent,
      currentSessionId: sltContext.metadata?.currentSessionId
    })

    await this.sltService.finalizeSlt(sltContext.sltJti)
    this.cookieService.clearSltCookie(res)

    return result
  }

  /**
   * Phương thức tập trung để cập nhật mật khẩu, thu hồi phiên và gửi thông báo.
   * Có thể được gọi từ nhiều luồng khác nhau (đặt lại mật khẩu, thay đổi mật khẩu).
   */
  async performPasswordUpdate(params: {
    userId: number
    newPassword?: string
    revokeAllSessions: boolean
    ipAddress: string
    userAgent: string
    currentSessionId?: string
  }): Promise<{ message: string; data?: { sessionsRevoked: boolean; revokedCount?: number } }> {
    const { userId, newPassword, revokeAllSessions, ipAddress, userAgent, currentSessionId } = params

    if (!newPassword) {
      this.logger.error(`Password update attempt for user ${userId} failed: New password was not provided.`)
      throw AuthError.MissingNewPasswordInContext()
    }

    const hashedPassword = await this.hashingService.hash(newPassword)
    // First, update the password
    await this.userRepository.updatePassword(userId, hashedPassword)
    // Then, fetch the user with the profile included to solve the type issue
    const user = await this.userRepository.findByIdWithDetails(userId)
    if (!user) {
      // This should theoretically not be reached if the update was successful
      this.logger.error(`User with ID ${userId} not found after password update.`)
      throw AuthError.InternalServerError()
    }

    let revokedCount = 0
    if (revokeAllSessions) {
      const result = await this.sessionsService.invalidateAllUserSessions(userId, 'password_change', currentSessionId)
      revokedCount = result.deletedSessionsCount
      this.logger.log(`All sessions for user ${userId} have been revoked due to password change.`)
    }

    try {
      const userAgentInfo = this.userAgentService.parse(userAgent)
      const locationInfo = await this.geolocationService.getLocationFromIP(ipAddress)
      await this.emailService.sendPasswordChangedEmail(user.email, {
        userName: user.userProfile?.username || user.email.split('@')[0],
        details: [
          {
            label: 'email.Email.common.details.ipAddress',
            value: ipAddress
          },
          {
            label: 'email.Email.common.details.location',
            value: locationInfo.display
          },
          {
            label: 'email.Email.common.details.device',
            value: `${userAgentInfo.browser || 'Unknown'} on ${userAgentInfo.os || 'Unknown'}`
          }
        ]
      })
    } catch (emailError) {
      this.logger.error(`Failed to send password change notification email to user ${userId}: ${emailError.message}`)
      // Do not throw error to the client as the password update was successful
    }

    return {
      message: 'auth.success.password.resetSuccess',
      data: {
        sessionsRevoked: revokeAllSessions,
        revokedCount
      }
    }
  }

  async changePassword(
    activeUser: ActiveUserData,
    dto: ChangePasswordDto,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<any> {
    const { id: userId, sessionId, deviceId } = activeUser
    const { currentPassword, newPassword, revokeOtherSessions } = dto
    this.logger.debug(`[changePassword] User ${userId} attempting to change password.`)

    const user = await this.userRepository.findByIdWithDetails(userId)
    if (!user) {
      throw AuthError.EmailNotFound()
    }

    if (!user.password) {
      throw AuthError.PasswordChangeNotAllowed()
    }

    const isPasswordValid = await this.hashingService.compare(currentPassword, user.password)
    if (!isPasswordValid) {
      throw AuthError.InvalidPassword()
    }

    const hashedPassword = await this.hashingService.hash(newPassword)

    this.logger.debug(`[changePassword] Current password is valid. Initiating verification flow for user ${userId}.`)
    return this.authVerificationService.initiateVerification(
      {
        userId,
        deviceId,
        email: user.email,
        ipAddress,
        userAgent,
        purpose: TypeOfVerificationCode.CHANGE_PASSWORD,
        metadata: {
          newPassword: hashedPassword,
          revokeAllSessions: revokeOtherSessions,
          currentSessionId: sessionId
        }
      },
      res
    )
  }
}
