import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma, RecoveryCode } from '@prisma/client'
import { PrismaTransactionClient } from 'src/shared/types/prisma.type'

@Injectable()
export class RecoveryCodeRepository {
  private readonly logger = new Logger(RecoveryCodeRepository.name)

  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Bắt đầu transaction
   */
  async tx<T>(callback: (tx: PrismaTransactionClient) => Promise<T>): Promise<T> {
    return this.prismaService.$transaction(async (tx) => {
      return callback(tx)
    })
  }

  /**
   * Tìm mã khôi phục chưa sử dụng
   */
  async findUnusedRecoveryCodesByUserId(userId: number): Promise<RecoveryCode[]> {
    return this.prismaService.recoveryCode.findMany({
      where: {
        userId,
        used: false
      }
    })
  }

  /**
   * Tìm tất cả mã khôi phục của người dùng
   */
  async findByUserId(userId: number): Promise<RecoveryCode[]> {
    return this.prismaService.recoveryCode.findMany({
      where: {
        userId,
        used: false
      }
    })
  }

  /**
   * Tạo mã khôi phục mới
   */
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

  /**
   * Đánh dấu mã khôi phục đã sử dụng
   */
  async markRecoveryCodeAsUsed(codeId: number): Promise<RecoveryCode> {
    return this.prismaService.recoveryCode.update({
      where: { id: codeId },
      data: {
        used: true
      }
    })
  }

  /**
   * Xác minh mã khôi phục
   */
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

  /**
   * Xóa tất cả mã khôi phục của người dùng
   */
  async deleteAllUserRecoveryCodes(userId: number): Promise<Prisma.BatchPayload> {
    return this.prismaService.recoveryCode.deleteMany({
      where: { userId }
    })
  }

  /**
   * Xóa các mã khôi phục của người dùng
   * @param userId ID của người dùng
   * @param tx Transaction client (tùy chọn)
   */
  async deleteRecoveryCodes(userId: number, tx?: PrismaTransactionClient): Promise<Prisma.BatchPayload> {
    const prisma = tx || this.prismaService
    return prisma.recoveryCode.deleteMany({
      where: { userId }
    })
  }

  /**
   * Xóa một mã khôi phục cụ thể
   * @param id ID của mã khôi phục
   * @param tx Transaction client (tùy chọn)
   */
  async deleteRecoveryCode(id: number, tx?: PrismaTransactionClient): Promise<RecoveryCode> {
    const prisma = tx || this.prismaService
    return prisma.recoveryCode.delete({
      where: { id }
    })
  }

  /**
   * Tìm recovery code theo mã code
   */
  async findByCode(code: string): Promise<RecoveryCode | null> {
    try {
      return await this.prismaService.recoveryCode.findFirst({
        where: {
          code: code,
          used: false
        }
      })
    } catch (error) {
      this.logger.error(`Lỗi khi tìm recovery code: ${error.message}`, error.stack)
      return null
    }
  }
}
