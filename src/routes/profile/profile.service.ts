import { Inject, Injectable, Logger, forwardRef } from '@nestjs/common'
import { UserAuthRepository } from '../auth/shared/repositories/user-auth.repository'
import { AuthError } from '../auth/auth.error'
import { ChangePasswordDto, ProfileResponseDto } from './profile.dto'
import { ProfileRepository } from './profile.repository'
import {
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  HASHING_SERVICE,
  SESSIONS_SERVICE,
  TWO_FACTOR_SERVICE,
  USER_AGENT_SERVICE
} from 'src/shared/constants/injection.tokens'
import { HashingService } from '../auth/shared/services/common/hashing.service'
import { TwoFactorService } from '../auth/modules/two-factor/two-factor.service'
import { SessionsService } from '../auth/modules/sessions/session.service'
import { EmailService } from '../auth/shared/services/common/email.service'
import { AccessTokenPayload } from '../auth/shared/auth.types'
import { GeolocationService } from '../auth/shared/services/common/geolocation.service'
import { UserAgentService } from '../auth/shared/services/common/user-agent.service'
import { I18nService } from 'nestjs-i18n'

@Injectable()
export class ProfileService {
  private readonly logger = new Logger(ProfileService.name)

  constructor(
    private readonly userAuthRepository: UserAuthRepository,
    private readonly profileRepository: ProfileRepository,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    @Inject(forwardRef(() => TwoFactorService)) private readonly twoFactorService: TwoFactorService,
    @Inject(SESSIONS_SERVICE) private readonly sessionsService: SessionsService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService,
    private readonly i18nService: I18nService
  ) {}

  async getProfile(userId: number): Promise<ProfileResponseDto> {
    this.logger.debug(`Fetching profile for user ID: ${userId}`)

    const user = await this.userAuthRepository.findById(userId)
    if (!user) {
      this.logger.warn(`[getProfile] User with ID ${userId} not found.`)
      throw AuthError.EmailNotFound()
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...userWithoutPassword } = user

    return {
      id: userWithoutPassword.id,
      email: userWithoutPassword.email,
      role: userWithoutPassword.role.name,
      status: userWithoutPassword.status,
      twoFactorEnabled: userWithoutPassword.twoFactorEnabled,
      googleId: userWithoutPassword.googleId,
      createdAt: userWithoutPassword.createdAt,
      updatedAt: userWithoutPassword.updatedAt,
      userProfile: userWithoutPassword.userProfile
        ? {
            firstName: userWithoutPassword.userProfile.firstName,
            lastName: userWithoutPassword.userProfile.lastName,
            username: userWithoutPassword.userProfile.username,
            phoneNumber: userWithoutPassword.userProfile.phoneNumber,
            avatar: userWithoutPassword.userProfile.avatar
          }
        : null
    }
  }

  async changePassword(
    activeUser: AccessTokenPayload,
    dto: ChangePasswordDto,
    ipAddress: string,
    userAgent: string
  ): Promise<void> {
    const { userId, sessionId } = activeUser
    const { currentPassword, newPassword, revokeOtherSessions, twoFactorCode, twoFactorMethod } = dto
    this.logger.debug(`[changePassword] User ${userId} attempting to change password.`)

    const user = await this.userAuthRepository.findById(userId)
    if (!user) {
      throw AuthError.EmailNotFound()
    }

    if (!user.password) {
      throw AuthError.BadRequest('Cannot change password for accounts without a password (e.g., social login).')
    }

    const isPasswordValid = await this.hashingService.compare(currentPassword, user.password)
    if (!isPasswordValid) {
      throw AuthError.InvalidPassword()
    }

    if (user.twoFactorEnabled) {
      if (!twoFactorCode) {
        throw AuthError.BadRequest('Two-factor code is required.')
      }
      await this.twoFactorService.verifyCode(twoFactorCode, {
        userId,
        method: twoFactorMethod
      })
      this.logger.debug(`[changePassword] 2FA verification successful for user ${userId}.`)
    }

    const hashedPassword = await this.hashingService.hash(newPassword)
    await this.userAuthRepository.updatePassword(userId, hashedPassword)
    this.logger.log(`[changePassword] Password changed successfully for user ${userId}.`)

    if (revokeOtherSessions) {
      await this.sessionsService.invalidateAllUserSessions(userId, 'password_change', sessionId)
      this.logger.log(`[changePassword] Revoked all other sessions for user ${userId}.`)
    }

    const locationResult = await this.geolocationService.getLocationFromIP(ipAddress)
    const uaInfo = this.userAgentService.parse(userAgent)
    const details = [
      {
        label: this.i18nService.t('email.Email.common.details.time'),
        value: new Date().toLocaleString('vi-VN', {
          timeZone: locationResult.timezone || 'Asia/Ho_Chi_Minh',
          dateStyle: 'full',
          timeStyle: 'long'
        })
      },
      {
        label: this.i18nService.t('email.Email.common.details.ipAddress'),
        value: ipAddress
      },
      {
        label: this.i18nService.t('email.Email.common.details.device'),
        value: `${uaInfo.browser} on ${uaInfo.os}`
      }
    ]

    await this.emailService.sendPasswordChangedEmail(user.email, {
      userName: user.userProfile?.username ?? user.email,
      details
    })
  }
}
