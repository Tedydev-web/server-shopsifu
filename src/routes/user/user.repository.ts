import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/providers/prisma/prisma.service'
import { User, Prisma, Role, UserProfile, Permission, TwoFactorMethodType } from '@prisma/client'
import { UserError } from './user.error'
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library'
import { Permission as PermissionModel } from 'src/routes/permission/permission.model'

export interface TwoFactorSettings {
  secret: string | null
  method: TwoFactorMethodType | null
}

export type UserWithProfileAndRole = User & {
  userProfile: UserProfile | null
  role: Role & { permissions?: Permission[] }
}

const userInclude = {
  userProfile: true,
  role: {
    include: {
      permissions: {
        include: {
          permission: true
        }
      }
    }
  }
}

@Injectable()
export class UserRepository {
  private readonly logger = new Logger(UserRepository.name)
  constructor(private readonly prisma: PrismaService) {}

  private toUserWithPermissions(
    userWithRolePermissions: (User & { userProfile: UserProfile | null; role: Role & { permissions: any[] } }) | null
  ): UserWithProfileAndRole | null {
    if (!userWithRolePermissions) {
      return null
    }

    const { role, ...restOfUser } = userWithRolePermissions
    if (!role) {
      return userWithRolePermissions as UserWithProfileAndRole
    }

    const { permissions: rolePermissions, ...restOfRole } = role
    const permissions = rolePermissions?.map((p: any) => p.permission).filter(Boolean) || []

    return {
      ...restOfUser,
      role: {
        ...restOfRole,
        permissions
      }
    }
  }

  async create(data: Prisma.UserCreateInput): Promise<User> {
    return this.prisma.user.create({ data })
  }

  async createWithProfile(data: CreateUserWithProfileData): Promise<UserWithProfileAndRole> {
    const {
      email,
      password,
      roleId,
      username,
      firstName,
      lastName,
      phoneNumber,
      bio,
      avatar,
      countryCode,
      googleId,
      googleAvatar
    } = data

    try {
      const user = await this.prisma.user.create({
        data: {
          email,
          password,
          googleId,
          roleId,
          status: 'ACTIVE',
          userProfile: {
            create: {
              firstName: firstName || null,
              lastName: lastName || null,
              username,
              phoneNumber: phoneNumber || null,
              bio: bio || null,
              avatar: avatar || googleAvatar || null,
              countryCode: countryCode || 'VN'
            }
          }
        },
        include: userInclude
      })
      return this.toUserWithPermissions(user as any)
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          // Unique constraint violation
          const target = error.meta?.target as string[]
          if (target?.includes('email')) {
            throw UserError.AlreadyExists(email)
          } else if (target?.includes('username')) {
            throw UserError.UsernameAlreadyExists(username)
          }
        }
      }
      this.logger.error('Failed to create user with profile:', error)
      throw UserError.CreateFailed()
    }
  }

  async findAll(
    params: {
      skip?: number
      take?: number
      cursor?: Prisma.UserWhereUniqueInput
      where?: Prisma.UserWhereInput
      orderBy?: Prisma.UserOrderByWithRelationInput
    } = {}
  ): Promise<User[]> {
    const { skip, take, cursor, where, orderBy } = params
    return this.prisma.user.findMany({ skip, take, cursor, where, orderBy })
  }

  async findById(id: number): Promise<User | null> {
    return this.prisma.user.findUnique({ where: { id } })
  }

  async findByIdWithDetails(userId: number): Promise<UserWithProfileAndRole | null> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: userInclude
    })
    return this.toUserWithPermissions(user as any)
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({ where: { email } })
  }

  async findByEmailWithDetails(email: string): Promise<UserWithProfileAndRole | null> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: userInclude
    })
    return this.toUserWithPermissions(user as any)
  }

  async findByEmailOrUsername(emailOrUsername: string): Promise<UserWithProfileAndRole | null> {
    const user = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: emailOrUsername }, { userProfile: { username: emailOrUsername } }]
      },
      include: userInclude
    })
    return this.toUserWithPermissions(user as any)
  }

  async findByGoogleId(googleId: string): Promise<UserWithProfileAndRole | null> {
    const user = await this.prisma.user.findFirst({
      where: { googleId },
      include: userInclude
    })
    return this.toUserWithPermissions(user as any)
  }

  async update(id: number, data: Prisma.UserUpdateInput): Promise<User> {
    return this.prisma.user.update({
      where: { id },
      data
    })
  }

  async remove(id: number): Promise<User> {
    return this.prisma.user.delete({ where: { id } })
  }

  async enableTwoFactor(userId: number, secret: string, method: TwoFactorMethodType): Promise<User> {
    this.logger.debug(`Enabling 2FA for user ${userId} with method ${method}`)
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: true,
        twoFactorSecret: secret,
        twoFactorMethod: method,
        twoFactorVerifiedAt: new Date()
      }
    })
  }

  async disableTwoFactor(userId: number): Promise<User> {
    this.logger.debug(`Disabling 2FA for user ${userId}`)
    return this.prisma.user.update({
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
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorSecret: data.secret,
        twoFactorMethod: data.method
      }
    })
  }

  async updateGoogleId(userId: number, googleId: string | null): Promise<User> {
    return this.prisma.user.update({
      where: { id: userId },
      data: { googleId }
    })
  }

  async updatePassword(userId: number, password: string): Promise<UserWithProfileAndRole> {
    const user = await this.prisma.user.update({
      where: { id: userId },
      data: {
        password,
        passwordChangedAt: new Date()
      },
      include: userInclude
    })
    return this.toUserWithPermissions(user as any)
  }
}

export type CreateUserWithProfileData = {
  email: string
  password: string
  roleId: number
  username: string
  firstName?: string | null
  lastName?: string | null
  phoneNumber?: string | null
  bio?: string | null
  avatar?: string | null
  countryCode?: string | null
  googleId?: string
  googleAvatar?: string
}
