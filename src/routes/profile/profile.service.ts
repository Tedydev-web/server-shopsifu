import {
  Injectable,
  Logger,
  NotFoundException,
  ConflictException,
  BadRequestException,
  HttpStatus
} from '@nestjs/common'
import { ProfileRepository, UserWithProfileAndRole, UserProfileAtomicUpdateData } from './profile.repo'
import { UpdateProfileBodyType, UserProfileResponseType } from './profile.model'
import { Prisma } from '@prisma/client'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { v4 as uuidv4 } from 'uuid'
import ms from 'ms'
import envConfig from 'src/shared/config'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { OtpService } from 'src/routes/auth/providers/otp.service'
import { TypeOfVerificationCode } from 'src/routes/auth/constants/auth.constants'
import { ProfileError } from './profile.error'

@Injectable()
export class ProfileService {
  private readonly logger = new Logger(ProfileService.name)

  constructor(
    private readonly profileRepository: ProfileRepository,
    private readonly i18nService: I18nService,
    private readonly otpService: OtpService
  ) {}

  private async _getUserOrFail(userId: number): Promise<UserWithProfileAndRole> {
    const userWithProfile = await this.profileRepository.findUserWithProfileAndRoleById(userId)
    if (!userWithProfile) {
      const message = await this.i18nService.translate('Error.User.NotFound', {
        lang: I18nContext.current()?.lang,
        args: { id: userId.toString() }
      })
      throw new NotFoundException(message)
    }
    return userWithProfile
  }

  async getCurrentUserProfile(userId: number): Promise<UserProfileResponseType> {
    const userWithProfile = await this._getUserOrFail(userId)

    return {
      id: userWithProfile.id,
      email: userWithProfile.email,
      isEmailVerified: userWithProfile.isEmailVerified,
      status: userWithProfile.status,
      role: userWithProfile.role.name,
      twoFactorEnabled: userWithProfile.twoFactorEnabled ?? false,
      userProfile: userWithProfile.userProfile
        ? {
            firstName: userWithProfile.userProfile.firstName,
            lastName: userWithProfile.userProfile.lastName,
            username: userWithProfile.userProfile.username,
            avatar: userWithProfile.userProfile.avatar,
            bio: userWithProfile.userProfile.bio,
            phoneNumber: userWithProfile.userProfile.phoneNumber,
            countryCode: userWithProfile.userProfile.countryCode
          }
        : null
    }
  }

  async updateCurrentUserProfile(
    userId: number,
    data: UpdateProfileBodyType,
    ipAddress?: string,
    userAgent?: string
  ): Promise<UserProfileResponseType> {
    const userBeforeUpdate = await this._getUserOrFail(userId)

    const dataForRepoUpsert: UserProfileAtomicUpdateData = {}

    const { phoneNumber, countryCode, ...restOfDataFromDto } = data

    Object.assign(dataForRepoUpsert, restOfDataFromDto)

    const auditLogDetails: Prisma.JsonObject = {
      updatedFields: Object.keys(data),
      oldValues: {},
      newValues: data
    }

    if (userBeforeUpdate.userProfile) {
      if (!auditLogDetails.oldValues || typeof auditLogDetails.oldValues !== 'object') {
        auditLogDetails.oldValues = {}
      }
      for (const key of Object.keys(data)) {
        if (
          Object.prototype.hasOwnProperty.call(userBeforeUpdate.userProfile, key) &&
          userBeforeUpdate.userProfile[key] !== undefined
        ) {
          ;(auditLogDetails.oldValues as Prisma.JsonObject)[key] = userBeforeUpdate.userProfile[key]
        }
      }
    }

    if (data.username && data.username !== userBeforeUpdate.userProfile?.username) {
      if (data.username.length < 3 || data.username.length > 30) {
        const message = await this.i18nService.translate('Error.Profile.Username.Length', {
          lang: I18nContext.current()?.lang,
          args: { min: 3, max: 30 }
        })
        throw new BadRequestException(message)
      }
      if (!/^[a-zA-Z0-9_]+$/.test(data.username)) {
        const message = await this.i18nService.translate('Error.Profile.Username.InvalidChars', {
          lang: I18nContext.current()?.lang
        })
        throw new BadRequestException(message)
      }
      const existingProfileWithUsername = await this.profileRepository.findUserProfileByUsername(data.username)
      if (existingProfileWithUsername && existingProfileWithUsername.userId !== userId) {
        const message = await this.i18nService.translate('Error.Profile.Username.Taken', {
          lang: I18nContext.current()?.lang
        })
        throw new ConflictException(message)
      }
    }

    if (phoneNumber !== undefined) {
      if (phoneNumber === null) {
        dataForRepoUpsert.phoneNumber = null
        dataForRepoUpsert.countryCode = null
        dataForRepoUpsert.isPhoneNumberVerified = false
        dataForRepoUpsert.phoneNumberVerifiedAt = null
      } else {
        if (
          phoneNumber !== userBeforeUpdate.userProfile?.phoneNumber ||
          countryCode !== userBeforeUpdate.userProfile?.countryCode
        ) {
          const existingProfileWithPhoneNumber = await this.profileRepository.findUserProfileByPhoneNumber(phoneNumber)
          if (existingProfileWithPhoneNumber && existingProfileWithPhoneNumber.userId !== userId) {
            const message = await this.i18nService.translate('Error.Profile.PhoneNumber.Taken', {
              lang: I18nContext.current()?.lang
            })
            throw new ConflictException(message)
          }
          dataForRepoUpsert.phoneNumber = phoneNumber
          dataForRepoUpsert.countryCode = countryCode

          dataForRepoUpsert.isPhoneNumberVerified = false
          dataForRepoUpsert.phoneNumberVerifiedAt = null
        }
      }
    } else if (
      countryCode !== undefined &&
      countryCode !== userBeforeUpdate.userProfile?.countryCode &&
      userBeforeUpdate.userProfile?.phoneNumber
    ) {
      dataForRepoUpsert.countryCode = countryCode
    }

    const updatedUserProfile = await this.profileRepository.updateUserProfile(userId, dataForRepoUpsert)

    if (!updatedUserProfile) {
      const message = await this.i18nService.translate('Error.Profile.UpdateFailed', {
        lang: I18nContext.current()?.lang
      })
      throw new NotFoundException(message)
    }

    return this.getCurrentUserProfile(userId)
  }

  async requestEmailChange(
    userId: number,
    newEmail: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ message: string }> {
    const lang = I18nContext.current()?.lang || 'en'

    const user = await this._getUserOrFail(userId)

    if (user.email === newEmail) {
      throw ProfileError.EmailUnchanged()
    }

    if (user.pendingEmail === newEmail) {
      throw ProfileError.PendingEmailMatchesCurrent()
    }

    const existingUserWithNewEmail = await this.profileRepository.findUserByEmail(newEmail)
    if (existingUserWithNewEmail && existingUserWithNewEmail.id !== userId) {
      throw ProfileError.EmailAlreadyExists(newEmail)
    }

    const otherUserWithThisPendingEmail = await this.profileRepository.findUserByPendingEmail(newEmail)
    if (otherUserWithThisPendingEmail && otherUserWithThisPendingEmail.id !== userId) {
      throw ProfileError.EmailAlreadyExists(newEmail)
    }

    const emailVerificationToken = uuidv4()
    const tokenExpiresInMs = ms(envConfig.EMAIL_VERIFICATION_TOKEN_EXPIRES_IN || '1h')
    const emailVerificationTokenExpiresAt = new Date(Date.now() + tokenExpiresInMs)
    const emailVerificationSentAt = new Date()

    await this.profileRepository.setUserPendingEmail(
      userId,
      newEmail,
      emailVerificationToken,
      emailVerificationTokenExpiresAt,
      emailVerificationSentAt,
      false
    )

    try {
      await this.otpService.sendOTP(newEmail, TypeOfVerificationCode.VERIFY_NEW_EMAIL, userId)

      const message = await this.i18nService.translate('Success.Profile.Email.ChangeOtpSent', {
        lang,
        args: { email: newEmail }
      })
      return { message }
    } catch (error) {
      await this.profileRepository.setUserPendingEmail(
        userId,
        user.pendingEmail,
        user.emailVerificationToken,
        user.emailVerificationTokenExpiresAt,
        user.emailVerificationSentAt,
        user.isEmailVerified
      )

      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'OTP_SEND_FAILED', 'Error.Auth.Otp.FailedToSend')
    }
  }

  async verifyNewEmail(
    userId: number,
    tokenFromQuery: string,
    otpFromQuery: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<UserProfileResponseType> {
    const lang = I18nContext.current()?.lang || 'en'

    const user = await this._getUserOrFail(userId)

    if (!user.pendingEmail || !user.emailVerificationToken || !user.emailVerificationTokenExpiresAt) {
      throw ProfileError.NoPendingEmailChange()
    }

    if (user.emailVerificationToken !== tokenFromQuery) {
      throw ProfileError.InvalidEmailVerificationToken()
    }

    if (new Date() > user.emailVerificationTokenExpiresAt) {
      throw ProfileError.EmailVerificationTokenExpired()
    }

    try {
      await this.otpService.verifyOtpOnly(
        user.pendingEmail,
        otpFromQuery,
        TypeOfVerificationCode.VERIFY_NEW_EMAIL,
        userId,
        ipAddress,
        userAgent
      )
    } catch (error) {
      throw new ApiException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        'OTP_VERIFICATION_FAILED',
        'Error.Auth.Otp.FailedToVerify'
      )
    }

    const oldEmail = user.email
    const newEmail = user.pendingEmail

    await this.profileRepository.confirmNewUserEmail(userId, newEmail)

    return this.getCurrentUserProfile(userId)
  }
}
