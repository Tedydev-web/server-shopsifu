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

  async findById(userId: number): Promise<UserWithProfileAndRole | null> {
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

  async updateTwoFactorSettings(userId: number, data: TwoFactorSettings): Promise<User> {
    return this.prismaService.user.update({
      where: { id: userId },
      data
    })
  }

  async updateGoogleId(userId: number, googleId: string): Promise<User> {
    return this.prismaService.user.update({
      where: { id: userId },
      data: { googleId }
    })
  }

  async doesUsernameExist(username: string): Promise<boolean> {
    const count = await this.prismaService.userProfile.count({
      where: { username }
    })
    return count > 0
  }
}
