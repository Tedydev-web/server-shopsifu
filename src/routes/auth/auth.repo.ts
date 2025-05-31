import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma, PrismaClient, RecoveryCode, User } from '@prisma/client'

type PrismaTransactionClient = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

@Injectable()
export class AuthRepository {
  constructor(protected readonly prismaService: PrismaService) {}

  private getClient(prismaClient?: PrismaTransactionClient): PrismaTransactionClient | PrismaService {
    return prismaClient || this.prismaService
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
