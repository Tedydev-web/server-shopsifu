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
import { AuditLogService, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
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
    private readonly auditLogService: AuditLogService,
    private readonly i18nService: I18nService,
    private readonly otpService: OtpService
  ) {}

  private async _getUserOrFail(userId: number): Promise<UserWithProfileAndRole> {
    const userWithProfile = await this.profileRepository.findUserWithProfileAndRoleById(userId)
    if (!userWithProfile) {
      this.logger.warn(`User with ID ${userId} not found for profile operation.`)
      const message = await this.i18nService.translate('Error.User.NotFound', {
        lang: I18nContext.current()?.lang,
        args: { id: userId.toString() }
      })
      throw new NotFoundException(message)
    }
    return userWithProfile
  }

  async getCurrentUserProfile(userId: number): Promise<UserProfileResponseType> {
    this.logger.debug(`Fetching current user profile for user ID: ${userId}`)
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
    this.logger.debug(`Updating profile for user ID: ${userId} with data: ${JSON.stringify(data)}`)
    const userBeforeUpdate = await this._getUserOrFail(userId)

    const dataForRepoUpsert: UserProfileAtomicUpdateData = {}

    const { phoneNumber, countryCode, ...restOfDataFromDto } = data

    Object.assign(dataForRepoUpsert, restOfDataFromDto)

    const auditLogDetails: Prisma.JsonObject = {
      updatedFields: Object.keys(data),
      oldValues: {},
      newValues: data
    }

    // Populate oldValues for audit log
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
        this.logger.warn(
          `Username '${data.username}' is already taken by user ID: ${existingProfileWithUsername.userId}`
        )
        const message = await this.i18nService.translate('Error.Profile.Username.Taken', {
          lang: I18nContext.current()?.lang
        })
        throw new ConflictException(message)
      }
    }

    // Handle phone number update
    if (phoneNumber !== undefined) {
      if (phoneNumber === null) {
        // User wants to remove phone number
        dataForRepoUpsert.phoneNumber = null
        dataForRepoUpsert.countryCode = null // Also clear country code
        dataForRepoUpsert.isPhoneNumberVerified = false // Reset verification status
        dataForRepoUpsert.phoneNumberVerifiedAt = null
      } else {
        // User wants to update or set phone number
        if (
          phoneNumber !== userBeforeUpdate.userProfile?.phoneNumber ||
          countryCode !== userBeforeUpdate.userProfile?.countryCode
        ) {
          const existingProfileWithPhoneNumber = await this.profileRepository.findUserProfileByPhoneNumber(phoneNumber)
          if (existingProfileWithPhoneNumber && existingProfileWithPhoneNumber.userId !== userId) {
            this.logger.warn(
              `Phone number '${phoneNumber}' is already taken by user ID: ${existingProfileWithPhoneNumber.userId}`
            )
            const message = await this.i18nService.translate('Error.Profile.PhoneNumber.Taken', {
              lang: I18nContext.current()?.lang
            })
            throw new ConflictException(message)
          }
          dataForRepoUpsert.phoneNumber = phoneNumber
          dataForRepoUpsert.countryCode = countryCode // countryCode can be null if not provided with phoneNumber
          // Since it's not verified, set verification status to false
          dataForRepoUpsert.isPhoneNumberVerified = false
          dataForRepoUpsert.phoneNumberVerifiedAt = null
        }
      }
    } else if (
      countryCode !== undefined &&
      countryCode !== userBeforeUpdate.userProfile?.countryCode &&
      userBeforeUpdate.userProfile?.phoneNumber
    ) {
      // Case: phoneNumber is not in data, but countryCode is and has changed, and a phone number already exists.
      // This means we update only the countryCode for the existing phone number.
      dataForRepoUpsert.countryCode = countryCode
    }

    const updatedUserProfile = await this.profileRepository.updateUserProfile(userId, dataForRepoUpsert)

    if (!updatedUserProfile) {
      // This case should ideally not happen if upsert is used correctly
      this.logger.error(`Failed to update user profile for user ID: ${userId}`)
      await this.auditLogService.record({
        action: 'UPDATE_USER_PROFILE_FAILURE',
        userId,
        userEmail: userBeforeUpdate.email,
        status: AuditLogStatus.FAILURE,
        ipAddress,
        userAgent,
        details: auditLogDetails,
        errorMessage: 'ProfileRepository.updateUserProfile returned null'
      })
      const message = await this.i18nService.translate('Error.Profile.UpdateFailed', {
        lang: I18nContext.current()?.lang
      })
      throw new NotFoundException(message) // Or InternalServerErrorException
    }

    await this.auditLogService.record({
      action: 'UPDATE_USER_PROFILE_SUCCESS',
      userId,
      userEmail: userBeforeUpdate.email,
      status: AuditLogStatus.SUCCESS,
      ipAddress,
      userAgent,
      details: auditLogDetails
    })

    this.logger.log(`User profile updated successfully for user ID: ${userId}`)
    return this.getCurrentUserProfile(userId) // Return the full, updated profile
  }

  async requestEmailChange(
    userId: number,
    newEmail: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ message: string }> {
    this.logger.debug(`User ID ${userId} requested to change email to ${newEmail}`)
    const lang = I18nContext.current()?.lang || 'en'

    const user = await this._getUserOrFail(userId)

    if (user.email === newEmail) {
      throw ProfileError.EmailUnchanged()
    }

    // Check if the new email is already set as pending for this user
    if (user.pendingEmail === newEmail) {
      this.logger.warn(`User ID ${userId} requested to change to an email that is already pending: ${newEmail}`)
      // Option 1: Throw an error indicating it's already pending
      // throw ProfileError.PendingEmailAlreadySet(); // You would need to define this error
      // Option 2: Resend OTP (perhaps with cooldown). For now, let's assume error or specific handling.
      // For now, we can use an existing error or create a more specific one.
      // Let's use PendingEmailMatchesCurrent for now, which implies it's the same as the one they are trying to set as pending again.
      throw ProfileError.PendingEmailMatchesCurrent()
    }

    const existingUserWithNewEmail = await this.profileRepository.findUserByEmail(newEmail)
    if (existingUserWithNewEmail && existingUserWithNewEmail.id !== userId) {
      throw ProfileError.EmailAlreadyExists(newEmail)
    }
    // Also check if this newEmail is pending for *another* user
    const otherUserWithThisPendingEmail = await this.profileRepository.findUserByPendingEmail(newEmail)
    if (otherUserWithThisPendingEmail && otherUserWithThisPendingEmail.id !== userId) {
      throw ProfileError.EmailAlreadyExists(newEmail)
    }

    const emailVerificationToken = uuidv4()
    const tokenExpiresInMs = ms(envConfig.EMAIL_VERIFICATION_TOKEN_EXPIRES_IN || '1h')
    const emailVerificationTokenExpiresAt = new Date(Date.now() + tokenExpiresInMs)
    const emailVerificationSentAt = new Date()

    // Store pending email and token details
    await this.profileRepository.setUserPendingEmail(
      userId,
      newEmail,
      emailVerificationToken,
      emailVerificationTokenExpiresAt,
      emailVerificationSentAt,
      false // isEmailVerified should be false for the pending email itself
    )

    try {
      // Send OTP to the new (pending) email address
      await this.otpService.sendOTP(newEmail, TypeOfVerificationCode.VERIFY_NEW_EMAIL, userId)

      this.auditLogService.recordAsync({
        action: 'REQUEST_EMAIL_CHANGE_SUCCESS',
        userId,
        userEmail: user.email, // Log the original email
        status: AuditLogStatus.SUCCESS,
        ipAddress,
        userAgent,
        details: {
          oldEmail: user.email,
          pendingEmail: newEmail,
          tokenGenerated: !!emailVerificationToken,
          otpSentToPendingEmail: true
        } as Prisma.JsonObject
      })

      const message = await this.i18nService.translate('Success.Profile.Email.ChangeOtpSent', {
        lang,
        args: { email: newEmail }
      })
      return { message }
    } catch (error) {
      this.logger.error(
        `Failed to send OTP for email change to ${newEmail} for user ID ${userId}. Reverting pending email state.`,
        error
      )

      // Important: Revert the pending email state if OTP sending fails
      await this.profileRepository.setUserPendingEmail(
        userId,
        user.pendingEmail, // Previous pending email (could be null)
        user.emailVerificationToken, // Previous token
        user.emailVerificationTokenExpiresAt, // Previous expiry
        user.emailVerificationSentAt, // Previous sentAt
        user.isEmailVerified // This refers to the primary email's verification status, should remain unchanged here
      )

      this.auditLogService.recordAsync({
        action: 'REQUEST_EMAIL_CHANGE_OTP_FAIL',
        userId,
        userEmail: user.email,
        status: AuditLogStatus.FAILURE,
        ipAddress,
        userAgent,
        errorMessage: error.message,
        details: { pendingEmail: newEmail, oldEmail: user.email, reason: 'OTP_SEND_FAILED' } as Prisma.JsonObject
      })
      // Provide a generic error to the user
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
    this.logger.debug(
      `User ID ${userId} attempting to verify new email with token (first 8 chars): ${tokenFromQuery.substring(0, 8)}... and OTP.`
    )
    const lang = I18nContext.current()?.lang || 'en'

    const user = await this._getUserOrFail(userId)

    if (!user.pendingEmail || !user.emailVerificationToken || !user.emailVerificationTokenExpiresAt) {
      this.auditLogService.recordAsync({
        action: 'VERIFY_NEW_EMAIL_FAIL',
        userId,
        userEmail: user.email,
        status: AuditLogStatus.FAILURE,
        ipAddress,
        userAgent,
        errorMessage: 'No pending email change found or token/expiry missing.',
        details: { providedToken: tokenFromQuery, providedOtp: otpFromQuery } as Prisma.JsonObject
      })
      throw ProfileError.NoPendingEmailChange()
    }

    if (user.emailVerificationToken !== tokenFromQuery) {
      this.auditLogService.recordAsync({
        action: 'VERIFY_NEW_EMAIL_FAIL',
        userId,
        userEmail: user.email,
        status: AuditLogStatus.FAILURE,
        ipAddress,
        userAgent,
        errorMessage: 'Invalid email verification token.',
        details: { providedToken: tokenFromQuery, expectedToken: user.emailVerificationToken } as Prisma.JsonObject
      })
      throw ProfileError.InvalidEmailVerificationToken()
    }

    if (new Date() > user.emailVerificationTokenExpiresAt) {
      // Optionally, clear the pending email fields if token is expired
      // await this.profileRepository.setUserPendingEmail(userId, null, null, null, null, user.isEmailVerified);
      this.auditLogService.recordAsync({
        action: 'VERIFY_NEW_EMAIL_FAIL',
        userId,
        userEmail: user.email,
        status: AuditLogStatus.FAILURE,
        ipAddress,
        userAgent,
        errorMessage: 'Email verification token expired.',
        details: { tokenExpiry: user.emailVerificationTokenExpiresAt.toISOString() } as Prisma.JsonObject
      })
      throw ProfileError.EmailVerificationTokenExpired()
    }

    try {
      // Verify the OTP against the pendingEmail
      await this.otpService.verifyOtpOnly(
        user.pendingEmail, // Email to verify against is the pendingEmail
        otpFromQuery,
        TypeOfVerificationCode.VERIFY_NEW_EMAIL,
        userId, // userId for audit and matching in OtpService
        ipAddress,
        userAgent
      )
    } catch (error) {
      this.logger.warn(
        `OTP verification failed for new email ${user.pendingEmail} for user ID ${userId}: ${error.message}`
      )
      this.auditLogService.recordAsync({
        action: 'VERIFY_NEW_EMAIL_OTP_FAIL',
        userId,
        userEmail: user.email,
        status: AuditLogStatus.FAILURE,
        ipAddress,
        userAgent,
        errorMessage: error.message || 'OTP_VERIFICATION_FAILED',
        details: { pendingEmail: user.pendingEmail, providedOtp: otpFromQuery } as Prisma.JsonObject
      })
      // Let the original OTP error (InvalidOTPException, OTPExpiredException) propagate
      throw error
    }

    // If OTP is verified, proceed to update the user's email
    const oldEmail = user.email
    const newEmail = user.pendingEmail

    await this.profileRepository.confirmNewUserEmail(userId, newEmail)

    this.auditLogService.recordAsync({
      action: 'VERIFY_NEW_EMAIL_SUCCESS',
      userId,
      userEmail: newEmail, // The new email is now the primary email
      status: AuditLogStatus.SUCCESS,
      ipAddress,
      userAgent,
      details: { oldEmail, newEmail } as Prisma.JsonObject
    })

    // Optionally send a notification email about the successful email change
    // await this.emailService.sendEmailChangedNotification(userId, oldEmail, newEmail);

    this.logger.log(`User ID ${userId} successfully verified and changed email from ${oldEmail} to ${newEmail}`)
    return this.getCurrentUserProfile(userId)
  }
}
