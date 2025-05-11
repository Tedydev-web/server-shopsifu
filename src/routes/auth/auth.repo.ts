import { Injectable } from '@nestjs/common'
import {
  DeviceType,
  RefreshTokenType,
  RegisterBodyType,
  RoleType,
  VerificationCodeType
} from 'src/routes/auth/auth.model'
import { OtpTokenType as OtpTokenModelType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCodeType, TypeOfOtpTokenType } from 'src/shared/constants/auth.constant'
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
    payload: Pick<VerificationCodeType, 'email' | 'type' | 'code' | 'expiresAt' | 'salt'>
  ): Promise<VerificationCodeType> {
    return this.prismaService.verificationCode.upsert({
      where: {
        email_code_type: {
          email: payload.email,
          code: payload.code,
          type: payload.type
        }
      },
      create: {
        ...payload,
        attempts: 0
      },
      update: {
        code: payload.code,
        salt: payload.salt,
        expiresAt: payload.expiresAt,
        attempts: 0
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

  async findVerificationCodesByEmailAndType(
    email: string,
    type: TypeOfVerificationCodeType
  ): Promise<VerificationCodeType[]> {
    return this.prismaService.verificationCode.findMany({
      where: {
        email,
        type
      }
    })
  }

  createRefreshToken(data: { token: string; userId: number; expiresAt: Date; deviceId: number }) {
    return this.prismaService.refreshToken.create({
      data
    })
  }

  createDevice(
    data: Pick<DeviceType, 'userId' | 'userAgent' | 'ip'> & Partial<Pick<DeviceType, 'lastActive' | 'isActive'>>
  ) {
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

  createOtpToken(data: {
    token: string
    userId: number
    type: TypeOfOtpTokenType
    expiresAt: Date
    deviceId: number
  }): Promise<OtpTokenModelType> {
    return this.prismaService.otpToken.create({
      data
    })
  }

  findUniqueOtpToken(uniqueObject: { token: string }): Promise<OtpTokenModelType | null> {
    return this.prismaService.otpToken.findUnique({
      where: uniqueObject
    })
  }

  findUniqueOtpTokenWithDevice(uniqueObject: {
    token: string
  }): Promise<(OtpTokenModelType & { device: DeviceType }) | null> {
    return this.prismaService.otpToken.findUnique({
      where: uniqueObject,
      include: {
        device: true
      }
    })
  }

  deleteOtpToken(uniqueObject: { token: string }): Promise<OtpTokenModelType> {
    return this.prismaService.otpToken.delete({
      where: uniqueObject
    })
  }

  async updateVerificationCodeAttempts(
    uniqueValue: {
      email_code_type: {
        email: string
        code: string
        type: TypeOfVerificationCodeType
      }
    },
    attempts: number
  ): Promise<VerificationCodeType> {
    return this.prismaService.verificationCode.update({
      where: uniqueValue,
      data: {
        attempts
      }
    })
  }
}
