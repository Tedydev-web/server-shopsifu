import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma, User, UserProfile } from '@prisma/client'

export type UserProfileAtomicUpdateData = Partial<{
  firstName?: string | null
  lastName?: string | null
  username?: string | null
  avatar?: string | null
  bio?: string | null
  phoneNumber?: string | null
  countryCode?: string | null
  isPhoneNumberVerified?: boolean | null
  phoneNumberVerifiedAt?: Date | null
}>

export type UserWithProfileAndRole = User & {
  userProfile: UserProfile | null
  role: { name: string }
}

@Injectable()
export class ProfileRepository {
  private readonly logger = new Logger(ProfileRepository.name)

  constructor(private readonly prismaService: PrismaService) {}

  async findUserWithProfileAndRoleById(userId: number): Promise<UserWithProfileAndRole | null> {
    return this.prismaService.user.findUnique({
      where: { id: userId },
      include: {
        userProfile: true,
        role: {
          select: { name: true }
        }
      }
    })
  }

  async updateUserProfile(userId: number, data: UserProfileAtomicUpdateData): Promise<UserProfile | null> {
    const updatePayload: Prisma.UserProfileUpdateInput = {}

    for (const key in data) {
      if (Object.prototype.hasOwnProperty.call(data, key) && data[key] !== undefined) {
        updatePayload[key] = data[key]
      }
    }
    if ('userId' in updatePayload) {
      delete updatePayload.userId
    }

    const userProfile = await this.prismaService.userProfile.upsert({
      where: { userId },
      update: updatePayload,
      create: {
        userId,
        firstName: data.firstName,
        lastName: data.lastName,
        username: data.username,
        avatar: data.avatar,
        bio: data.bio,
        phoneNumber: data.phoneNumber,
        countryCode: data.countryCode,

        isPhoneNumberVerified: typeof data.isPhoneNumberVerified === 'boolean' ? data.isPhoneNumberVerified : false,
        phoneNumberVerifiedAt: data.phoneNumberVerifiedAt
      }
    })
    return userProfile
  }

  async findUserProfileByUsername(username: string): Promise<UserProfile | null> {
    return this.prismaService.userProfile.findUnique({
      where: { username }
    })
  }

  async findUserProfileByPhoneNumber(phoneNumber: string): Promise<UserProfile | null> {
    return this.prismaService.userProfile.findUnique({
      where: { phoneNumber }
    })
  }

  async findUserByEmail(email: string): Promise<User | null> {
    return this.prismaService.user.findUnique({
      where: { email }
    })
  }

  async setUserPendingEmail(
    userId: number,
    pendingEmail: string | null,
    verificationToken: string | null,
    expiresAt: Date | null,
    sentAt: Date | null,
    isVerified: boolean = false
  ): Promise<User> {
    return this.prismaService.user.update({
      where: { id: userId },
      data: {
        pendingEmail,
        emailVerificationToken: verificationToken,
        emailVerificationTokenExpiresAt: expiresAt,
        emailVerificationSentAt: sentAt,
        isEmailVerified: isVerified
      }
    })
  }

  async findUserByEmailVerificationToken(token: string): Promise<User | null> {
    return this.prismaService.user.findFirst({
      where: {
        emailVerificationToken: token,
        emailVerificationTokenExpiresAt: { gt: new Date() }
      }
    })
  }

  async confirmNewUserEmail(userId: number, newEmail: string): Promise<User> {
    return this.prismaService.user.update({
      where: { id: userId },
      data: {
        email: newEmail,
        isEmailVerified: true,
        pendingEmail: null,
        emailVerificationToken: null,
        emailVerificationTokenExpiresAt: null,
        emailVerificationSentAt: null
      }
    })
  }

  async findUserByPendingEmail(pendingEmail: string): Promise<User | null> {
    return this.prismaService.user.findUnique({
      where: { pendingEmail }
    })
  }
}
