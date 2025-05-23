import { Injectable } from '@nestjs/common'
import { DeviceType, RefreshTokenType, RoleType } from 'src/routes/auth/auth.model'
import { TokenTypeType, TypeOfVerificationCodeType } from 'src/shared/constants/auth.constant'
import { UserType } from 'src/shared/models/shared-user.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import {
  Prisma,
  PrismaClient,
  RecoveryCode,
  VerificationCodeType as PrismaVerificationCodeEnum,
  User,
  VerificationCode as PrismaVerificationCodeModel
} from '@prisma/client'

type PrismaTransactionClient = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

@Injectable()
export class AuthRepository {
  constructor(private readonly prismaService: PrismaService) {}

  private getClient(prismaClient?: PrismaTransactionClient): PrismaTransactionClient | PrismaService {
    return prismaClient || this.prismaService
  }

  // Helper function, similar to the one in TokenService
  private basicDeviceFingerprint(userAgent: string | null | undefined): string {
    const uaToProcess = userAgent || '' // Normalize null, undefined to empty string

    const lowerUserAgent = uaToProcess.toLowerCase()
    const isMobile = /mobile|android|iphone|ipad|ipod/i.test(lowerUserAgent)
    const browserMatch = lowerUserAgent.match(/(chrome|safari|firefox|edge|opera|trident|msie)\/?[\\s]*([\\d.]+)/i)
    const osMatch = lowerUserAgent.match(/(windows|mac|linux|android|ios|iphone|ipad)\\s*([\\d.]*)/i)

    const deviceType = isMobile ? 'mobile' : 'desktop'
    const browser = browserMatch ? browserMatch[1].toLowerCase() : 'unknown'
    const os = osMatch ? osMatch[1].toLowerCase() : 'unknown'

    return `${deviceType}-${os}-${browser}`
  }

  async createUser(
    user: Pick<UserType, 'email' | 'name' | 'password' | 'phoneNumber' | 'roleId'>,
    prismaClient?: PrismaTransactionClient
  ): Promise<Omit<UserType, 'password' | 'twoFactorSecret'>> {
    const client = this.getClient(prismaClient)
    return client.user.create({
      data: user,
      omit: {
        password: true,
        twoFactorSecret: true
      }
    })
  }

  async createUserIncludeRole(
    user: Pick<UserType, 'email' | 'name' | 'password' | 'phoneNumber' | 'avatar' | 'roleId'>,
    prismaClient?: PrismaTransactionClient
  ): Promise<UserType & { role: RoleType }> {
    const client = this.getClient(prismaClient)
    return client.user.create({
      data: user,
      include: {
        role: true
      }
    })
  }

  async createVerificationCode(
    payload: Pick<PrismaVerificationCodeModel, 'email' | 'code' | 'type' | 'expiresAt'>,
    prismaClient?: PrismaTransactionClient
  ): Promise<PrismaVerificationCodeModel> {
    const client = this.getClient(prismaClient)
    return await client.verificationCode.upsert({
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
    uniqueValue: Prisma.VerificationCodeWhereUniqueInput,
    prismaClient?: PrismaTransactionClient
  ): Promise<PrismaVerificationCodeModel | null> {
    const client = this.getClient(prismaClient)
    return await client.verificationCode.findUnique({
      where: uniqueValue
    })
  }

  createRefreshToken(
    data: { token: string; userId: number; expiresAt: Date; deviceId: number; rememberMe: boolean },
    prismaClient?: PrismaTransactionClient
  ) {
    const client = this.getClient(prismaClient)
    return client.refreshToken.create({
      data
    })
  }

  createDevice(
    data: Pick<DeviceType, 'userId' | 'userAgent' | 'ip'> & Partial<Pick<DeviceType, 'lastActive' | 'isActive'>>,
    prismaClient?: PrismaTransactionClient
  ) {
    const client = this.getClient(prismaClient)
    return client.device.create({
      data
    })
  }

  async findUniqueUserIncludeRole(
    uniqueObject: { email: string } | { id: number },
    prismaClient?: PrismaTransactionClient
  ): Promise<(UserType & { role: RoleType }) | null> {
    const client = this.getClient(prismaClient)
    return client.user.findUnique({
      where: uniqueObject,
      include: {
        role: true
      }
    })
  }

  async findUniqueRefreshTokenIncludeUserRole(
    uniqueObject: {
      token: string
    },
    prismaClient?: PrismaTransactionClient
  ): Promise<(RefreshTokenType & { user: UserType & { role: RoleType } }) | null> {
    const client = this.getClient(prismaClient)
    return client.refreshToken.findUnique({
      where: {
        token: uniqueObject.token,
        used: false,
        expiresAt: {
          gt: new Date()
        }
      },
      include: {
        user: {
          include: {
            role: true
          }
        }
      }
    })
  }

  updateDevice(
    deviceId: number,
    data: Partial<DeviceType>,
    prismaClient?: PrismaTransactionClient
  ): Promise<DeviceType> {
    const client = this.getClient(prismaClient)
    return client.device.update({
      where: {
        id: deviceId
      },
      data
    }) as unknown as Promise<DeviceType>
  }

  deleteRefreshToken(
    uniqueObject: { token: string },
    prismaClient?: PrismaTransactionClient
  ): Promise<RefreshTokenType | null> {
    const client = this.getClient(prismaClient)
    return client.refreshToken.findUnique({ where: uniqueObject }).then((token) => {
      if (!token) {
        return null
      }
      return client.refreshToken.delete({ where: uniqueObject })
    })
  }

  updateUser(
    where: Prisma.UserWhereUniqueInput,
    data: Prisma.UserUpdateInput,
    prismaClient?: PrismaTransactionClient
  ): Promise<UserType> {
    const client = this.getClient(prismaClient)
    return client.user.update({
      where,
      data
    }) as Promise<UserType>
  }

  async deleteVerificationCode(
    uniqueValue: Prisma.VerificationCodeWhereUniqueInput,
    prismaClient?: PrismaTransactionClient
  ): Promise<PrismaVerificationCodeModel> {
    const client = this.getClient(prismaClient)
    return await client.verificationCode.delete({
      where: uniqueValue
    })
  }

  async deleteVerificationCodesByEmailAndType(
    data: {
      email: string
      type: TypeOfVerificationCodeType
    },
    prismaClient?: PrismaTransactionClient
  ): Promise<Prisma.BatchPayload> {
    const client = this.getClient(prismaClient)
    return await client.verificationCode.deleteMany({
      where: {
        email: data.email,
        type: data.type as PrismaVerificationCodeEnum
      }
    })
  }

  async createVerificationToken(
    data: {
      token: string
      email: string
      type: PrismaVerificationCodeEnum
      tokenType: TokenTypeType
      expiresAt: Date
      userId?: number
      deviceId?: number
      metadata?: string
    },
    prismaClient?: PrismaTransactionClient
  ): Promise<PrismaVerificationCodeModel> {
    const client = this.getClient(prismaClient)
    const createData: Prisma.VerificationTokenCreateInput = {
      token: data.token,
      email: data.email,
      type: data.type,
      tokenType: data.tokenType,
      expiresAt: data.expiresAt,
      metadata: data.metadata
    }

    if (data.userId !== undefined) {
      createData.user = { connect: { id: data.userId } }
    }
    if (data.deviceId !== undefined) {
      createData.device = { connect: { id: data.deviceId } }
    }

    return (await client.verificationToken.create({
      data: createData
    })) as unknown as PrismaVerificationCodeModel
  }

  async findUniqueVerificationToken(
    uniqueObject: { token: string },
    prismaClient?: PrismaTransactionClient
  ): Promise<PrismaVerificationCodeModel | null> {
    const client = this.getClient(prismaClient)
    return (await client.verificationToken.findUnique({
      where: uniqueObject
    })) as unknown as PrismaVerificationCodeModel | null
  }

  async findVerificationTokens(
    filter: {
      email: string
      type: TypeOfVerificationCodeType
      tokenType: TokenTypeType
    },
    prismaClient?: PrismaTransactionClient
  ): Promise<PrismaVerificationCodeModel[]> {
    const client = this.getClient(prismaClient)
    return (await client.verificationToken.findMany({
      where: {
        email: filter.email,
        type: filter.type as PrismaVerificationCodeEnum,
        tokenType: filter.tokenType
      }
    })) as unknown as PrismaVerificationCodeModel[]
  }

  async updateVerificationToken(
    data: { token: string; metadata?: string },
    prismaClient?: PrismaTransactionClient
  ): Promise<PrismaVerificationCodeModel> {
    const client = this.getClient(prismaClient)
    return (await client.verificationToken.update({
      where: { token: data.token },
      data: { metadata: data.metadata }
    })) as unknown as PrismaVerificationCodeModel
  }

  async deleteVerificationToken(
    uniqueObject: { token: string },
    prismaClient?: PrismaTransactionClient
  ): Promise<PrismaVerificationCodeModel> {
    const client = this.getClient(prismaClient)
    return (await client.verificationToken.delete({
      where: uniqueObject
    })) as unknown as PrismaVerificationCodeModel
  }

  async deleteVerificationTokenByEmailAndType(
    email: string,
    type: TypeOfVerificationCodeType,
    tokenType: TokenTypeType,
    prismaClient?: PrismaTransactionClient
  ): Promise<Prisma.BatchPayload> {
    const client = this.getClient(prismaClient)
    return await client.verificationToken.deleteMany({
      where: {
        email,
        type: type as PrismaVerificationCodeEnum,
        tokenType
      }
    })
  }

  async findOrCreateDevice(
    data: Pick<DeviceType, 'userId' | 'userAgent' | 'ip'>,
    prismaClient?: PrismaTransactionClient
  ): Promise<DeviceType> {
    const client = this.getClient(prismaClient)
    const existingDevice = await client.device.findFirst({
      where: {
        userId: data.userId,
        userAgent: data.userAgent,
        isActive: true
      }
    })

    if (existingDevice) {
      return this.updateDevice(
        existingDevice.id,
        {
          ip: data.ip,
          lastActive: new Date()
        },
        client as PrismaTransactionClient
      )
    }
    return this.createDevice(data, client as PrismaTransactionClient)
  }

  async validateDevice(
    deviceId: number,
    userAgent: string,
    ip: string,
    prismaClient?: PrismaTransactionClient
  ): Promise<boolean> {
    const client = this.getClient(prismaClient)
    const device = await client.device.findUnique({
      where: {
        id: deviceId
      }
    })

    if (!device || !device.isActive) {
      return false
    }

    const currentFingerprint = this.basicDeviceFingerprint(userAgent)
    const storedFingerprint = this.basicDeviceFingerprint(device.userAgent)
    const isFingerprintMatched = currentFingerprint === storedFingerprint

    await this.updateDevice(
      deviceId,
      {
        lastActive: new Date(),
        ip
      },
      client as PrismaTransactionClient
    )

    return isFingerprintMatched
  }

  async createManyRecoveryCodes(
    data: Prisma.RecoveryCodeCreateManyInput[],
    prismaClient?: PrismaTransactionClient
  ): Promise<Prisma.BatchPayload> {
    const client = this.getClient(prismaClient)
    return await client.recoveryCode.createMany({
      data
    })
  }

  async findUserWithRecoveryCodes(
    userId: number,
    prismaClient?: PrismaTransactionClient
  ): Promise<(User & { RecoveryCode: RecoveryCode[] }) | null> {
    const client = this.getClient(prismaClient)
    return await client.user.findUnique({
      where: { id: userId },
      include: { RecoveryCode: true }
    })
  }

  async updateRecoveryCode(
    id: number,
    data: Prisma.RecoveryCodeUpdateInput,
    prismaClient?: PrismaTransactionClient
  ): Promise<RecoveryCode> {
    const client = this.getClient(prismaClient)
    return await client.recoveryCode.update({
      where: { id },
      data
    })
  }

  async deleteRecoveryCodesByUserId(
    userId: number,
    prismaClient?: PrismaTransactionClient
  ): Promise<Prisma.BatchPayload> {
    const client = this.getClient(prismaClient)
    return await client.recoveryCode.deleteMany({
      where: { userId }
    })
  }
}
