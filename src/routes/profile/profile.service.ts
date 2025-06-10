import { Inject, Injectable, Logger, forwardRef } from '@nestjs/common'
import { ProfileResponseDto, UpdateProfileDto } from './profile.dto'
import { ProfileRepository } from './profile.repository'
import { HASHING_SERVICE } from 'src/shared/constants/injection.tokens'
import { HashingService } from '../../shared/services/hashing.service'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { ProfileError } from './profile.error'
import { UserRepository } from '../user/user.repository'

@Injectable()
export class ProfileService {
  private readonly logger = new Logger(ProfileService.name)

  constructor(
    private readonly userRepository: UserRepository,
    private readonly profileRepository: ProfileRepository,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    private readonly i18nService: I18nService<I18nTranslations>
  ) {}

  async getProfile(userId: number): Promise<ProfileResponseDto> {
    this.logger.debug(`Fetching profile for user ID: ${userId}`)

    const user = await this.userRepository.findByIdWithDetails(userId)
    if (!user) {
      this.logger.warn(`[getProfile] User with ID ${userId} not found.`)
      throw ProfileError.NotFound()
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

  async updateProfile(userId: number, dto: UpdateProfileDto): Promise<ProfileResponseDto> {
    this.logger.debug(`Updating profile for user ID: ${userId}`)

    const { username, phoneNumber, ...rest } = dto

    if (username) {
      const existing = await this.profileRepository.doesUsernameExist(username)
      if (existing) {
        // You should create a specific error for this
        throw ProfileError.AlreadyExists()
      }
    }

    if (phoneNumber) {
      const existing = await this.profileRepository.doesPhoneNumberExist(phoneNumber)
      if (existing) {
        // You should create a specific error for this
        throw ProfileError.AlreadyExists()
      }
    }

    await this.profileRepository.updateByUserId(userId, {
      username,
      phoneNumber,
      ...rest
    })

    return this.getProfile(userId)
  }
}
