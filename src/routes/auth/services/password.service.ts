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
import { ICookieService, ISessionService, ISLTService } from 'src/routes/auth/auth.types'
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

  async initiatePasswordReset(email: string, ipAddress: string, userAgent: string, res: Response) {
    const user = await this.userRepository.findByEmail(email)

    if (!user) {
      // Không tiết lộ email không tồn tại để tránh email enumeration attack
      return {
        message: 'auth.success.password.initiateReset'
      }
    }

    // Khởi tạo luồng xác thực (OTP/2FA) trước khi cho phép reset password
    return this.authVerificationService.initiateVerification(
      {
        userId: user.id,
        deviceId: 0, // Sẽ được tạo/cập nhật nếu cần trong verification service
        email: user.email,
        ipAddress,
        userAgent,
        purpose: TypeOfVerificationCode.RESET_PASSWORD
      },
      res
    )
  }

  async setNewPassword(
    sltCookieValue: string,
    dto: SetNewPasswordDto,
    ipAddress: string,
    userAgent: string,
    res: Response
  ) {
    // Validate SLT token và lấy context
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

  async performPasswordUpdate(params: {
    userId: number
    newPassword?: string
    revokeAllSessions: boolean
    ipAddress: string
    userAgent: string
    currentSessionId?: string
    isPasswordAlreadyHashed?: boolean
  }): Promise<{ message: string; data?: { sessionsRevoked: boolean; revokedCount?: number } }> {
    const {
      userId,
      newPassword,
      revokeAllSessions,
      ipAddress,
      userAgent,
      currentSessionId,
      isPasswordAlreadyHashed = false
    } = params

    if (!newPassword) {
      throw AuthError.MissingNewPasswordInContext()
    }

    // Only hash the password if it's not already hashed
    const hashedPassword = isPasswordAlreadyHashed ? newPassword : await this.hashingService.hash(newPassword)
    // First, update the password
    await this.userRepository.updatePassword(userId, hashedPassword)
    // Then, fetch the user with the profile included to solve the type issue
    const user = await this.userRepository.findByIdWithDetails(userId)
    if (!user) {
      // This should theoretically not be reached if the update was successful
      throw AuthError.InternalServerError()
    }

    let revokedCount = 0
    if (revokeAllSessions) {
      const result = await this.sessionsService.invalidateAllUserSessions(userId, 'password_change', currentSessionId)
      revokedCount = result.deletedSessionsCount
    }

    const userAgentInfo = this.userAgentService.parse(userAgent)
    const locationInfo = await this.geolocationService.getLocationFromIP(ipAddress || '')
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

    // Validate that new password is different from current password
    const isSamePassword = await this.hashingService.compare(newPassword, user.password)
    if (isSamePassword) {
      throw AuthError.SamePassword()
    }

    const hashedPassword = await this.hashingService.hash(newPassword)

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
