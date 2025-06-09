import { Inject, Injectable, Logger, forwardRef } from '@nestjs/common'
import { UserAuthRepository } from '../auth/repositories/user-auth.repository'
import { AuthError } from '../auth/auth.error'
import { ChangePasswordDto, ProfileResponseDto } from './profile.dto'
import { ProfileRepository } from './profile.repository'
import {
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  HASHING_SERVICE,
  SESSIONS_SERVICE,
  USER_AGENT_SERVICE
} from 'src/shared/constants/injection.tokens'
import { HashingService } from '../../shared/services/hashing.service'
import { SessionsService } from '../auth/services/session.service'
import { EmailService } from '../../shared/services/email.service'
import { AccessTokenPayload } from '../../shared/types/auth.types'
import { GeolocationService } from '../../shared/services/geolocation.service'
import { UserAgentService } from '../../shared/services/user-agent.service'
import { I18nService } from 'nestjs-i18n'
import { AuthVerificationService } from '../auth/services/auth-verification.service'
import { Response } from 'express'
import { TypeOfVerificationCode } from '../auth/auth.constants'
import { UserProfile, User } from '@prisma/client'

@Injectable()
export class ProfileService {
  private readonly logger = new Logger(ProfileService.name)

  constructor(
    private readonly userAuthRepository: UserAuthRepository,
    private readonly profileRepository: ProfileRepository,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    @Inject(SESSIONS_SERVICE) private readonly sessionsService: SessionsService,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(GEOLOCATION_SERVICE) private readonly geolocationService: GeolocationService,
    @Inject(USER_AGENT_SERVICE) private readonly userAgentService: UserAgentService,
    private readonly i18nService: I18nService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService
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
    userAgent: string,
    res: Response
  ): Promise<any> {
    const { userId, sessionId, deviceId } = activeUser
    const { currentPassword, newPassword, revokeOtherSessions } = dto
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
          hashedNewPassword: hashedPassword,
          revokeOtherSessions,
          sessionIdToExclude: sessionId
        }
      },
      res
    )
  }

  private async sendPasswordChangeEmail(
    user: User & { userProfile: UserProfile | null },
    ipAddress: string,
    userAgent: string
  ) {
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
      userName: user.userProfile?.username ?? user.email.split('@')[0],
      details
    })
  }
}
