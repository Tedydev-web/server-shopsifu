import { Injectable, Logger } from '@nestjs/common'
import * as OTPAuth from 'otpauth'
import envConfig from 'src/shared/config'
import { PrismaService } from './prisma.service'
import { Prisma, PrismaClient, RecoveryCode } from '@prisma/client'
import { HashingService } from './hashing.service'
import { TwoFactorMethodType, TwoFactorMethodTypeType } from 'src/shared/constants/auth.constant'
import { InvalidRecoveryCodeException, InvalidTOTPException } from 'src/routes/auth/auth.error'

// Kiểu cho Prisma Transaction Client, loại bỏ các phương thức không dùng trong transaction
type PrismaTransactionClient = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

/**
 * Dịch vụ quản lý xác thực hai yếu tố - phụ trách tạo, xác thực, và quản lý TOTP và recovery codes
 * Phiên bản cải thiện tuân thủ best practices:
 * - Quản lý đầy đủ các phương thức xác thực hai yếu tố
 * - Logging chi tiết và nhất quán
 * - JSDoc đầy đủ cho tất cả phương thức
 * - Xử lý các use case khác nhau
 */
@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name)

  constructor(
    private readonly prismaService: PrismaService,
    private readonly hashingService: HashingService
  ) {}

  /**
   * Tạo đối tượng TOTP với các thiết lập chuẩn
   * @private
   * @param email Email người dùng làm label cho TOTP
   * @param secret Secret key (tùy chọn)
   * @returns Đối tượng TOTP đã cấu hình
   */
  private createTOTP(email: string, secret?: string) {
    return new OTPAuth.TOTP({
      issuer: envConfig.APP_NAME,
      label: email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: secret || new OTPAuth.Secret()
    })
  }

  /**
   * Tạo secret key và URI cho TOTP
   * @param email Email người dùng
   * @returns Secret key và URI để tạo QR code
   */
  generateTOTPSecret(email: string) {
    this.logger.debug(`Generating TOTP secret for user: ${email}`)
    const totp = this.createTOTP(email)
    return {
      secret: totp.secret.base32,
      uri: totp.toString()
    }
  }

  /**
   * Xác thực mã TOTP
   * @param data Dữ liệu xác thực gồm email, mã và secret
   * @returns True nếu xác thực thành công, ngược lại là false
   */
  verifyTOTP({ email, token, secret }: { email: string; secret: string; token: string }): boolean {
    this.logger.debug(`Verifying TOTP for user: ${email}`)
    const totp = this.createTOTP(email, secret)
    const delta = totp.validate({ token, window: 1 })
    return delta !== null
  }

  /**
   * Tạo danh sách recovery codes mới
   * @param count Số lượng mã cần tạo (mặc định: 8)
   * @returns Danh sách recovery codes dưới dạng chuỗi
   */
  generateRecoveryCodes(count: number = 8): string[] {
    this.logger.debug(`Generating ${count} recovery codes`)
    const codes: string[] = []
    for (let i = 0; i < count; i++) {
      const group1 = Math.random().toString(36).substring(2, 7).toUpperCase()
      const group2 = Math.random().toString(36).substring(2, 7).toUpperCase()
      codes.push(`${group1}-${group2}`)
    }
    return codes
  }

  /**
   * Lưu recovery codes vào database
   * @param userId ID người dùng
   * @param recoveryCodes Danh sách recovery codes
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Kết quả tạo các recovery codes
   */
  async saveRecoveryCodes(
    userId: number,
    recoveryCodes: string[],
    tx?: PrismaTransactionClient
  ): Promise<Prisma.BatchPayload> {
    this.logger.debug(`Saving ${recoveryCodes.length} recovery codes for user ${userId}`)
    const client = tx || this.prismaService

    const hashedRecoveryCodes = await Promise.all(
      recoveryCodes.map(async (code) => ({
        userId,
        code: await this.hashingService.hash(code)
      }))
    )

    return client.recoveryCode.createMany({
      data: hashedRecoveryCodes
    })
  }

  /**
   * Xác thực recovery code
   * @param userId ID người dùng
   * @param recoveryCodeInput Mã recovery code cần xác thực
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Recovery code đã được xác thực
   * @throws InvalidRecoveryCodeException nếu mã không hợp lệ hoặc đã được sử dụng
   */
  async verifyRecoveryCode(userId: number, recoveryCodeInput: string, tx?: PrismaTransactionClient) {
    this.logger.debug(`Verifying recovery code for user ${userId}`)
    const client = tx || this.prismaService

    const userWithRecoveryCodes = await client.user.findUnique({
      where: { id: userId },
      include: { RecoveryCode: true }
    })

    if (
      !userWithRecoveryCodes ||
      !userWithRecoveryCodes.RecoveryCode ||
      userWithRecoveryCodes.RecoveryCode.length === 0
    ) {
      this.logger.warn(`No recovery codes found for user ${userId}`)
      throw InvalidRecoveryCodeException
    }

    let matchedCodeEntry: RecoveryCode | null = null
    for (const rcEntry of userWithRecoveryCodes.RecoveryCode) {
      if (await this.hashingService.compare(recoveryCodeInput, rcEntry.code)) {
        matchedCodeEntry = rcEntry
        break
      }
    }

    if (!matchedCodeEntry) {
      this.logger.warn(`Invalid recovery code provided for user ${userId}`)
      throw InvalidRecoveryCodeException
    }

    if (matchedCodeEntry.used) {
      this.logger.warn(`Used recovery code attempted for user ${userId}`)
      throw InvalidRecoveryCodeException
    }

    await client.recoveryCode.update({
      where: { id: matchedCodeEntry.id },
      data: { used: true }
    })

    this.logger.debug(`Recovery code successfully verified and marked as used for user ${userId}`)
    return matchedCodeEntry
  }

  /**
   * Lấy danh sách recovery codes chưa sử dụng của người dùng
   * @param userId ID người dùng
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Danh sách recovery codes chưa sử dụng
   */
  async getUnusedRecoveryCodes(userId: number, tx?: PrismaTransactionClient) {
    this.logger.debug(`Getting unused recovery codes for user ${userId}`)
    const client = tx || this.prismaService

    return client.recoveryCode.findMany({
      where: {
        userId,
        used: false
      }
    })
  }

  /**
   * Xóa tất cả recovery codes của người dùng
   * @param userId ID người dùng
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Kết quả xóa recovery codes
   */
  async deleteAllRecoveryCodes(userId: number, tx?: PrismaTransactionClient) {
    this.logger.debug(`Deleting all recovery codes for user ${userId}`)
    const client = tx || this.prismaService

    return client.recoveryCode.deleteMany({
      where: { userId }
    })
  }

  /**
   * Cập nhật trạng thái xác thực hai yếu tố của người dùng
   * @param userId ID người dùng
   * @param data Dữ liệu cập nhật
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Người dùng đã được cập nhật
   */
  async updateUserTwoFactorStatus(
    userId: number,
    data: {
      twoFactorEnabled: boolean
      twoFactorSecret?: string | null
      twoFactorMethod?: TwoFactorMethodTypeType | null
      twoFactorVerifiedAt?: Date | null
    },
    tx?: PrismaTransactionClient
  ) {
    this.logger.debug(`Updating 2FA status for user ${userId}: enabled=${data.twoFactorEnabled}`)
    const client = tx || this.prismaService

    return client.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: data.twoFactorEnabled,
        twoFactorSecret: data.twoFactorSecret,
        twoFactorMethod: data.twoFactorMethod,
        twoFactorVerifiedAt: data.twoFactorVerifiedAt
      }
    })
  }

  /**
   * Kiểm tra xem người dùng đã bật xác thực hai yếu tố chưa
   * @param userId ID người dùng
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Thông tin trạng thái xác thực hai yếu tố
   */
  async getUserTwoFactorStatus(userId: number, tx?: PrismaTransactionClient) {
    this.logger.debug(`Getting 2FA status for user ${userId}`)
    const client = tx || this.prismaService

    const user = await client.user.findUnique({
      where: { id: userId },
      select: {
        twoFactorEnabled: true,
        twoFactorMethod: true,
        twoFactorVerifiedAt: true
      }
    })

    return user
  }
}
