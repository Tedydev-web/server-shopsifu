import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/providers/prisma/prisma.service'
import { Prisma, RecoveryCode } from '@prisma/client'
import { PrismaTransactionClient } from 'src/shared/providers/prisma/prisma.type'

@Injectable()
export class RecoveryCodeRepository {
  private readonly logger = new Logger(RecoveryCodeRepository.name)

  constructor(private readonly prismaService: PrismaService) {}

  async tx<T>(callback: (tx: PrismaTransactionClient) => Promise<T>): Promise<T> {
    return this.prismaService.$transaction(async (tx) => {
      return callback(tx)
    })
  }

  async findUnusedRecoveryCodesByUserId(userId: number): Promise<RecoveryCode[]> {
    return this.prismaService.recoveryCode.findMany({
      where: {
        userId,
        used: false
      }
    })
  }

  async findByUserId(userId: number): Promise<RecoveryCode[]> {
    return this.prismaService.recoveryCode.findMany({
      where: {
        userId,
        used: false
      }
    })
  }

  async createRecoveryCodes(
    userId: number,
    hashedCodes: string[],
    tx?: PrismaTransactionClient
  ): Promise<RecoveryCode[]> {
    const prisma = tx || this.prismaService
    const created: RecoveryCode[] = []

    for (const code of hashedCodes) {
      created.push(
        await prisma.recoveryCode.create({
          data: {
            userId,
            code,
            used: false
          }
        })
      )
    }

    return created
  }

  async markRecoveryCodeAsUsed(codeId: number): Promise<RecoveryCode> {
    return this.prismaService.recoveryCode.update({
      where: { id: codeId },
      data: {
        used: true
      }
    })
  }

  async verifyRecoveryCode(userId: number, code: string): Promise<boolean> {
    const recoveryCode = await this.prismaService.recoveryCode.findFirst({
      where: {
        userId,
        code,
        used: false
      }
    })

    return !!recoveryCode
  }

  async deleteAllUserRecoveryCodes(userId: number): Promise<Prisma.BatchPayload> {
    return this.prismaService.recoveryCode.deleteMany({
      where: { userId }
    })
  }

  async deleteRecoveryCodes(userId: number, tx?: PrismaTransactionClient): Promise<Prisma.BatchPayload> {
    const prisma = tx || this.prismaService
    return prisma.recoveryCode.deleteMany({
      where: { userId }
    })
  }

  async deleteRecoveryCode(id: number, tx?: PrismaTransactionClient): Promise<RecoveryCode> {
    const prisma = tx || this.prismaService
    return prisma.recoveryCode.delete({
      where: { id }
    })
  }

  async findByCode(code: string): Promise<RecoveryCode | null> {
    try {
      return await this.prismaService.recoveryCode.findFirst({
        where: {
          code: code,
          used: false
        }
      })
    } catch {
      return null
    }
  }
}
