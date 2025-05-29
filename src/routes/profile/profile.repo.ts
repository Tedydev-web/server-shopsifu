import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma, User, UserProfile } from '@prisma/client'

// Kiểu dữ liệu mới cho phép tất cả các trường UserProfile có thể null hoặc undefined
// để Upsert có thể hoạt động đúng cách cho cả create và update.
export type UserProfileAtomicUpdateData = Partial<{
  firstName?: string | null
  lastName?: string | null
  username?: string | null
  avatar?: string | null
  bio?: string | null
  phoneNumber?: string | null
  countryCode?: string | null
  isPhoneNumberVerified?: boolean | null // Cho phép service quản lý
  phoneNumberVerifiedAt?: Date | null // Cho phép service quản lý
}>

export type UserWithProfileAndRole = User & {
  userProfile: UserProfile | null
  role: { name: string } // Chỉ cần tên của role
}

@Injectable()
export class ProfileRepository {
  private readonly logger = new Logger(ProfileRepository.name)

  constructor(private readonly prismaService: PrismaService) {}

  async findUserWithProfileAndRoleById(userId: number): Promise<UserWithProfileAndRole | null> {
    this.logger.debug(`Finding user with profile and role by ID: ${userId}`)
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
    this.logger.debug(`Updating user profile for user ID: ${userId} with data: ${JSON.stringify(data)}`)

    const updatePayload: Prisma.UserProfileUpdateInput = {}
    // Không cần khởi tạo createPayload ở đây nữa, sẽ xây dựng trực tiếp trong lệnh upsert

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
        userId, // userId được cung cấp trực tiếp
        firstName: data.firstName,
        lastName: data.lastName,
        username: data.username,
        avatar: data.avatar,
        bio: data.bio,
        phoneNumber: data.phoneNumber,
        countryCode: data.countryCode,
        // Xử lý isPhoneNumberVerified:
        // - Nếu là true/false, giữ nguyên.
        // - Nếu là null hoặc undefined, đặt thành false (mặc định khi tạo mới hoặc khi phoneNumber thay đổi mà không có xác minh).
        isPhoneNumberVerified: typeof data.isPhoneNumberVerified === 'boolean' ? data.isPhoneNumberVerified : false,
        phoneNumberVerifiedAt: data.phoneNumberVerifiedAt
      }
    })
    return userProfile
  }

  async findUserProfileByUsername(username: string): Promise<UserProfile | null> {
    this.logger.debug(`Finding user profile by username: ${username}`)
    return this.prismaService.userProfile.findUnique({
      where: { username }
    })
  }

  async findUserProfileByPhoneNumber(phoneNumber: string): Promise<UserProfile | null> {
    this.logger.debug(`Finding user profile by phone number: ${phoneNumber}`)
    return this.prismaService.userProfile.findUnique({
      where: { phoneNumber }
    })
  }

  async findUserByEmail(email: string): Promise<User | null> {
    this.logger.debug(`Finding user by email: ${email}`)
    return this.prismaService.user.findUnique({
      where: { email }
    })
  }

  async setUserPendingEmail(
    userId: number,
    pendingEmail: string | null, // Allow null to clear
    verificationToken: string | null,
    expiresAt: Date | null,
    sentAt: Date | null,
    isVerified: boolean = false // Default to false when setting pending email
  ): Promise<User> {
    this.logger.debug(`Setting pending email for user ID: ${userId} to ${pendingEmail}, isVerified: ${isVerified}`)
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

  // It's generally better to hash tokens before storing and querying.
  // This method assumes the token in the DB is hashed if needed, or the service layer handles hashing for query.
  async findUserByEmailVerificationToken(token: string): Promise<User | null> {
    this.logger.debug(`Finding user by email verification token (first 8 chars): ${token.substring(0, 8)}...`)
    // IMPORTANT: If tokens are hashed in DB, this query needs to change.
    // For now, assuming direct match or service hashes before calling.
    return this.prismaService.user.findFirst({
      where: {
        emailVerificationToken: token,
        emailVerificationTokenExpiresAt: { gt: new Date() } // Check for expiration
      }
    })
  }

  async confirmNewUserEmail(userId: number, newEmail: string): Promise<User> {
    this.logger.debug(`Confirming new email for user ID: ${userId} to ${newEmail}`)
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
    this.logger.debug(`Finding user by pending email: ${pendingEmail}`)
    return this.prismaService.user.findUnique({
      where: { pendingEmail }
    })
  }
}
