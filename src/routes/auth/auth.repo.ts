import { Injectable } from '@nestjs/common'
import { DeviceType, RoleType } from 'src/routes/auth/auth.model'
import { UserType } from 'src/shared/models/shared-user.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma, PrismaClient, RecoveryCode, User, Device, UserStatus } from '@prisma/client'
import { DeviceService } from 'src/routes/auth/providers/device.service'

type PrismaTransactionClient = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

@Injectable()
export class AuthRepository {
  constructor(
    protected readonly prismaService: PrismaService,
    private readonly deviceService: DeviceService
  ) {}

  private getClient(prismaClient?: PrismaTransactionClient): PrismaTransactionClient | PrismaService {
    return prismaClient || this.prismaService
  }

  async createUser(
    user: Pick<UserType, 'email' | 'name' | 'password' | 'phoneNumber' | 'roleId'> & { status?: UserStatus },
    prismaClient?: PrismaTransactionClient
  ): Promise<Omit<UserType, 'password' | 'twoFactorSecret'>> {
    const client = this.getClient(prismaClient)
    return await client.user.create({
      data: {
        email: user.email,
        name: user.name,
        password: user.password,
        phoneNumber: user.phoneNumber,
        roleId: user.roleId,
        status: user.status
      },
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
    return await client.user.create({
      data: user,
      include: {
        role: true
      }
    })
  }

  async createDevice(
    data: Pick<DeviceType, 'userId' | 'userAgent' | 'ip'> & Partial<Pick<DeviceType, 'lastActive' | 'isActive'>>,
    prismaClient?: PrismaTransactionClient
  ): Promise<Device> {
    const client = this.getClient(prismaClient)
    return await client.device.create({
      data
    })
  }

  async findUniqueUserIncludeRole(
    uniqueObject: { email: string } | { id: number },
    prismaClient?: PrismaTransactionClient
  ): Promise<(UserType & { role: RoleType }) | null> {
    const client = this.getClient(prismaClient)
    return await client.user.findUnique({
      where: uniqueObject,
      include: {
        role: true
      }
    })
  }

  async updateDevice(
    deviceId: number,
    data: Partial<DeviceType>,
    prismaClient?: PrismaTransactionClient
  ): Promise<Device> {
    const client = this.getClient(prismaClient)
    return await client.device.update({
      where: {
        id: deviceId
      },
      data
    })
  }

  async updateUser(
    where: Prisma.UserWhereUniqueInput,
    data: Prisma.UserUpdateInput,
    prismaClient?: PrismaTransactionClient
  ): Promise<User> {
    const client = this.getClient(prismaClient)
    return await client.user.update({
      where,
      data
    })
  }

  async findOrCreateDevice(
    data: Pick<DeviceType, 'userId' | 'userAgent' | 'ip'>,
    prismaClient?: PrismaTransactionClient
  ): Promise<Device> {
    const client = this.getClient(prismaClient)
    const existingDevice = await client.device.findFirst({
      where: {
        userId: data.userId,
        userAgent: data.userAgent,
        isActive: true
      }
    })

    if (existingDevice) {
      return await this.updateDevice(
        existingDevice.id,
        {
          ip: data.ip,
          lastActive: new Date()
        },
        client as PrismaTransactionClient
      )
    }
    return await this.createDevice(data, client as PrismaTransactionClient)
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

    const currentFingerprint = this.deviceService.basicDeviceFingerprint(userAgent)
    const storedFingerprint = this.deviceService.basicDeviceFingerprint(device.userAgent)
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
