import { Injectable } from '@nestjs/common'
import { DeviceType, RefreshTokenType, RoleType, VerificationCodeType, OtpTokenType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCodeType } from 'src/shared/constants/auth.constant'
import { UserType } from 'src/shared/models/shared-user.model'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class AuthRepository {
  constructor(private readonly prismaService: PrismaService) {}

  async createUser(
    user: Pick<UserType, 'email' | 'name' | 'password' | 'phoneNumber' | 'roleId'>
  ): Promise<Omit<UserType, 'password' | 'totpSecret'>> {
    return this.prismaService.user.create({
      data: user,
      omit: {
        password: true,
        totpSecret: true
      }
    })
  }

  async createUserInclueRole(
    user: Pick<UserType, 'email' | 'name' | 'password' | 'phoneNumber' | 'avatar' | 'roleId'>
  ): Promise<UserType & { role: RoleType }> {
    return this.prismaService.user.create({
      data: user,
      include: {
        role: true
      }
    })
  }

  async createVerificationCode(
    payload: Pick<VerificationCodeType, 'email' | 'type' | 'code' | 'expiresAt'> & { deviceId?: number }
  ): Promise<VerificationCodeType> {
    // Xóa các mã OTP cũ chưa sử dụng của cùng email và type
    await this.prismaService.verificationCode.deleteMany({
      where: {
        email: payload.email,
        type: payload.type,
        expiresAt: {
          gt: new Date()
        }
      }
    })

    return this.prismaService.verificationCode.upsert({
      where: {
        email_code_type: {
          email: payload.email,
          code: payload.code,
          type: payload.type
        }
      },
      create: {
        email: payload.email,
        code: payload.code,
        type: payload.type,
        expiresAt: payload.expiresAt,
        deviceId: payload.deviceId
      },
      update: {
        code: payload.code,
        expiresAt: payload.expiresAt,
        deviceId: payload.deviceId
      }
    })
  }

  async findUniqueVerificationCode(
    uniqueValue:
      | { id: number }
      | {
          email_code_type: {
            email: string
            code: string
            type: TypeOfVerificationCodeType
          }
        }
  ): Promise<VerificationCodeType | null> {
    return this.prismaService.verificationCode.findUnique({
      where: uniqueValue
    })
  }

  createRefreshToken(data: { token: string; userId: number; expiresAt: Date; deviceId: number }) {
    return this.prismaService.refreshToken.create({
      data
    })
  }

  createDevice(
    data: Pick<DeviceType, 'userAgent' | 'ip'> & Partial<Pick<DeviceType, 'lastActive' | 'isActive' | 'userId'>>
  ): Promise<DeviceType> {
    return this.prismaService.device.create({
      data
    })
  }

  async findUniqueUserIncludeRole(
    uniqueObject: { email: string } | { id: number }
  ): Promise<(UserType & { role: RoleType }) | null> {
    return this.prismaService.user.findUnique({
      where: uniqueObject,
      include: {
        role: true
      }
    })
  }

  async findUniqueRefreshTokenIncludeUserRole(uniqueObject: {
    token: string
  }): Promise<(RefreshTokenType & { user: UserType & { role: RoleType } }) | null> {
    return this.prismaService.refreshToken.findUnique({
      where: uniqueObject,
      include: {
        user: {
          include: {
            role: true
          }
        }
      }
    })
  }

  updateDevice(deviceId: number, data: Partial<DeviceType>): Promise<DeviceType> {
    return this.prismaService.device.update({
      where: {
        id: deviceId
      },
      data
    })
  }

  deleteRefreshToken(uniqueObject: { token: string }): Promise<RefreshTokenType> {
    return this.prismaService.refreshToken.delete({
      where: uniqueObject
    })
  }

  updateUser(where: { id: number } | { email: string }, data: Partial<Omit<UserType, 'id'>>): Promise<UserType> {
    return this.prismaService.user.update({
      where,
      data
    })
  }

  deleteVerificationCode(
    uniqueValue:
      | { id: number }
      | {
          email_code_type: {
            email: string
            code: string
            type: TypeOfVerificationCodeType
          }
        }
  ): Promise<VerificationCodeType> {
    return this.prismaService.verificationCode.delete({
      where: uniqueValue
    })
  }

  async createOtpToken(data: {
    token: string
    email: string
    userId?: number
    deviceId?: number
    type: TypeOfVerificationCodeType
    expiresAt: Date
  }): Promise<OtpTokenType> {
    // Xóa các OTP token cũ chưa sử dụng của cùng email và type
    await this.prismaService.otpToken.deleteMany({
      where: {
        email: data.email,
        type: data.type,
        expiresAt: {
          gt: new Date()
        }
      }
    })

    return this.prismaService.otpToken.create({
      data: {
        ...data
      }
    })
  }

  async findUniqueOtpToken(where: {
    token: string
    email: string
    type: TypeOfVerificationCodeType
  }): Promise<OtpTokenType | null> {
    return this.prismaService.otpToken.findFirst({
      where: {
        ...where,
        expiresAt: {
          gt: new Date()
        }
      }
    })
  }

  deleteOtpToken(uniqueValue: { token: string }): Promise<OtpTokenType> {
    return this.prismaService.otpToken.delete({
      where: uniqueValue
    })
  }
}
