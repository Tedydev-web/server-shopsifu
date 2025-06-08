import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { User, UserProfile, Role, Prisma, TwoFactorMethodType } from '@prisma/client'

export type UserWithProfileAndRole = User & {
  userProfile: UserProfile | null
  role: Role
}

export type CreateUserData = {
  email: string
  password: string
  firstName?: string
  lastName?: string
  username?: string
  phoneNumber?: string
  googleId?: string
  googleAvatar?: string
}

export interface TwoFactorSettings {
  twoFactorEnabled: boolean
  twoFactorSecret?: string | null
  twoFactorMethod?: TwoFactorMethodType | null
  twoFactorVerifiedAt?: Date | null
}

@Injectable()
export class UserAuthRepository {
  private readonly logger = new Logger(UserAuthRepository.name)

  constructor(private readonly prismaService: PrismaService) {}

  async findByEmail(email: string): Promise<UserWithProfileAndRole | null> {
    return this.prismaService.user.findUnique({
      where: { email },
      include: {
        userProfile: true,
        role: true
      }
    })
  }

  /**
   * Tìm người dùng theo ID
   * @param userId ID người dùng
   * @param select Tùy chọn chọn trường (tùy chọn)
   */
  async findById(userId: number, select?: Prisma.UserSelect): Promise<any> {
    if (select) {
      return this.prismaService.user.findUnique({
        where: { id: userId },
        select: {
          ...select,
          // Đảm bảo luôn chọn ID
          id: true
        }
      })
    }

    return this.prismaService.user.findUnique({
      where: { id: userId },
      include: {
        userProfile: true,
        role: true
      }
    })
  }

  async findByEmailOrUsername(emailOrUsername: string): Promise<UserWithProfileAndRole | null> {
    return this.prismaService.user.findFirst({
      where: {
        OR: [{ email: emailOrUsername }, { userProfile: { username: emailOrUsername } }]
      },
      include: {
        userProfile: true,
        role: true
      }
    })
  }

  async findByGoogleId(googleId: string): Promise<UserWithProfileAndRole | null> {
    return this.prismaService.user.findFirst({
      where: { googleId },
      include: {
        userProfile: true,
        role: true
      }
    })
  }

  async createUser(data: CreateUserData): Promise<UserWithProfileAndRole> {
    const { email, password, firstName, lastName, username, phoneNumber, googleId, googleAvatar } = data

    return this.prismaService.$transaction(async (tx) => {
      // Lấy vai trò client
      const clientRole = await tx.role.findFirst({
        where: { name: 'CLIENT' }
      })

      if (!clientRole) {
        throw new Error('Client role not found')
      }

      // Tạo username nếu chưa có
      const finalUsername = username || email.split('@')[0]

      // Tạo user
      const user = await tx.user.create({
        data: {
          email,
          password,
          googleId,
          roleId: clientRole.id,
          status: 'ACTIVE',
          userProfile: {
            create: {
              firstName: firstName || null,
              lastName: lastName || null,
              username: finalUsername,
              phoneNumber: phoneNumber || null,
              avatar: googleAvatar || null
            }
          }
        },
        include: {
          userProfile: true,
          role: true
        }
      })

      return user
    })
  }

  /**
   * Bật xác thực hai yếu tố
   * @param userId ID người dùng
   * @param secret Khóa bí mật
   * @param method Phương thức xác thực
   */
  async enableTwoFactor(userId: number, secret: string, method: TwoFactorMethodType): Promise<User> {
    this.logger.debug(`Bật 2FA cho người dùng ${userId} với phương thức ${method}`)
    return this.prismaService.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: true,
        twoFactorSecret: secret,
        twoFactorMethod: method,
        twoFactorVerifiedAt: new Date()
      }
    })
  }

  /**
   * Tắt xác thực hai yếu tố
   * @param userId ID người dùng
   */
  async disableTwoFactor(userId: number): Promise<User> {
    this.logger.debug(`Tắt 2FA cho người dùng ${userId}`)
    return this.prismaService.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorMethod: null,
        twoFactorVerifiedAt: null
      }
    })
  }

  async updateTwoFactorSettings(userId: number, data: TwoFactorSettings): Promise<User> {
    return this.prismaService.user.update({
      where: { id: userId },
      data
    })
  }

  async updateGoogleId(userId: number, googleId: string | null): Promise<User> {
    return this.prismaService.user.update({
      where: { id: userId },
      data: { googleId }
    })
  }

  async updatePassword(userId: number, password: string): Promise<User> {
    return this.prismaService.user.update({
      where: { id: userId },
      data: {
        password,
        passwordChangedAt: new Date()
      }
    })
  }

  async updateUser(userId: number, data: Partial<CreateUserData & { status?: string }>): Promise<User> {
    const { password, firstName, lastName, username, phoneNumber, status } = data

    return this.prismaService.$transaction(async (tx) => {
      const userUpdateData: Prisma.UserUpdateInput = {}
      if (password) userUpdateData.password = password
      if (status) userUpdateData.status = status as any

      const user = await tx.user.update({
        where: { id: userId },
        data: userUpdateData
      })

      const userProfileUpdateData: Prisma.UserProfileUpdateInput = {}
      if (firstName) userProfileUpdateData.firstName = firstName
      if (lastName) userProfileUpdateData.lastName = lastName
      if (username) userProfileUpdateData.username = username
      if (phoneNumber) userProfileUpdateData.phoneNumber = phoneNumber

      if (Object.keys(userProfileUpdateData).length > 0) {
        await tx.userProfile.update({
          where: { userId },
          data: userProfileUpdateData
        })
      }

      return user
    })
  }

  async doesUsernameExist(username: string): Promise<boolean> {
    const count = await this.prismaService.userProfile.count({
      where: { username }
    })
    return count > 0
  }

  async doesPhoneNumberExist(phoneNumber: string): Promise<boolean> {
    const count = await this.prismaService.userProfile.count({
      where: { phoneNumber }
    })
    return count > 0
  }
}
