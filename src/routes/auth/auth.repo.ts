import { Injectable } from '@nestjs/common'
import { DeviceType, RefreshTokenType, RoleType, VerificationCodeType } from 'src/routes/auth/auth.model'
import { TokenTypeType, TypeOfVerificationCodeType } from 'src/shared/constants/auth.constant'
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

  async createUserIncludeRole(
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
    payload: Pick<VerificationCodeType, 'email' | 'type' | 'code' | 'expiresAt'>
  ): Promise<VerificationCodeType> {
    return this.prismaService.verificationCode.upsert({
      where: {
        email_code_type: {
          email: payload.email,
          code: payload.code,
          type: payload.type
        }
      },
      create: payload,
      update: {
        code: payload.code,
        expiresAt: payload.expiresAt
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
    }) as unknown as Promise<DeviceType>
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

  async deleteVerificationCode(
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

  async deleteVerificationCodesByEmailAndType(data: {
    email: string
    type: TypeOfVerificationCodeType
  }): Promise<{ count: number }> {
    return this.prismaService.verificationCode.deleteMany({
      where: {
        email: data.email,
        type: data.type
      }
    })
  }

  // VerificationToken methods (thay thế OtpToken)
  createVerificationToken(data: {
    token: string
    email: string
    type: TypeOfVerificationCodeType
    tokenType: TokenTypeType
    expiresAt: Date
    userId?: number
    deviceId?: number
    metadata?: string
  }) {
    return this.prismaService.verificationToken.create({
      data
    })
  }

  findUniqueVerificationToken(uniqueObject: { token: string }) {
    return this.prismaService.verificationToken.findUnique({
      where: uniqueObject
    })
  }

  findVerificationTokens(filter: { email: string; type: TypeOfVerificationCodeType; tokenType: TokenTypeType }) {
    return this.prismaService.verificationToken.findMany({
      where: {
        email: filter.email,
        type: filter.type,
        tokenType: filter.tokenType
      }
    })
  }

  updateVerificationToken(data: { token: string; metadata?: string }) {
    return this.prismaService.verificationToken.update({
      where: { token: data.token },
      data: { metadata: data.metadata }
    })
  }

  deleteVerificationToken(uniqueObject: { token: string }) {
    return this.prismaService.verificationToken.delete({
      where: uniqueObject
    })
  }

  deleteVerificationTokenByEmailAndType(email: string, type: TypeOfVerificationCodeType, tokenType: TokenTypeType) {
    return this.prismaService.verificationToken.deleteMany({
      where: {
        email,
        type,
        tokenType
      }
    })
  }

  async findOrCreateDevice(data: Pick<DeviceType, 'userId' | 'userAgent' | 'ip'>): Promise<DeviceType> {
    // Tìm kiếm device hiện có dựa vào userId, userAgent và ip
    const existingDevice = await this.prismaService.device.findFirst({
      where: {
        userId: data.userId,
        userAgent: data.userAgent,
        isActive: true
      }
    })

    if (existingDevice) {
      // Nếu tìm thấy, cập nhật lastActive và ip
      return this.updateDevice(existingDevice.id, {
        ip: data.ip,
        lastActive: new Date()
      })
    }

    // Nếu không tìm thấy, tạo mới
    return this.createDevice(data)
  }

  async validateDevice(deviceId: number, userAgent: string, ip: string): Promise<boolean> {
    const device = await this.prismaService.device.findUnique({
      where: {
        id: deviceId
      }
    })

    if (!device) {
      return false
    }

    // Kiểm tra thiết bị có còn hoạt động không
    if (!device.isActive) {
      return false
    }

    // Trong thực tế, ta có thể thêm logic phức tạp hơn để xác minh thiết bị
    // Ví dụ: kiểm tra chi tiết userAgent, kiểm tra IP trong phạm vi địa lý...

    // Tùy vào mức độ nghiêm ngặt, có thể chỉ kiểm tra userAgent hoặc cả userAgent và IP
    // Đây là một cách tiếp cận cân bằng:
    const isUserAgentMatched = device.userAgent === userAgent

    // Cập nhật thiết bị với thông tin mới nhất
    await this.updateDevice(deviceId, {
      lastActive: new Date(),
      ip // Cập nhật IP mới
    })

    return isUserAgentMatched
  }
}
