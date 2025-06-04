import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { RecoveryCode, Prisma } from '@prisma/client'

@Injectable()
export class RecoveryCodeRepository {
  private readonly logger = new Logger(RecoveryCodeRepository.name)

  constructor(private readonly prismaService: PrismaService) {}

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
   * Tạo mã khôi phục mới
   */
  async createRecoveryCodes(userId: number, hashedCodes: string[]): Promise<RecoveryCode[]> {
    const created: RecoveryCode[] = []

    for (const code of hashedCodes) {
      created.push(
        await this.prismaService.recoveryCode.create({
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
}
