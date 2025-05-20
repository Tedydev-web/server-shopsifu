import { Injectable, Logger } from '@nestjs/common'
import {
  TokenType,
  TokenTypeType,
  TypeOfVerificationCode,
  TypeOfVerificationCodeType
} from 'src/shared/constants/auth.constant'
import envConfig from 'src/shared/config'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { EmailService } from 'src/shared/services/email.service'
import { addMilliseconds } from 'date-fns'
import ms from 'ms'
import { v4 as uuidv4 } from 'uuid'
import { generateOTP } from 'src/shared/helpers'
import { PrismaService } from './prisma.service'
import {
  Prisma,
  PrismaClient,
  VerificationCode as PrismaVerificationCodeModel,
  VerificationToken as PrismaVerificationToken,
  VerificationCodeType as PrismaVerificationCodeEnum
} from '@prisma/client'
import { ApiException } from 'src/shared/exceptions/api.exception'
import {
  InvalidOTPException,
  OTPExpiredException,
  FailedToSendOTPException,
  InvalidOTPTokenException,
  OTPTokenExpiredException,
  DeviceMismatchException
} from 'src/routes/auth/auth.error'

type PrismaTransactionClient = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name)

  constructor(
    private readonly prismaService: PrismaService,
    private readonly authRepository: AuthRepository,
    private readonly emailService: EmailService
  ) {}

  /**
   * Xác minh mã OTP 6 số
   * @param email Email người dùng
   * @param code Mã OTP 6 số
   * @param type Loại mã xác thực (đăng ký, quên mật khẩu, v.v.)
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Đối tượng VerificationCode nếu hợp lệ
   * @throws InvalidOTPException, OTPExpiredException
   */
  async validateVerificationCode({
    email,
    code,
    type,
    tx
  }: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
    tx?: PrismaTransactionClient
  }): Promise<PrismaVerificationCodeModel> {
    const client = tx || this.prismaService

    const verificationCode = await this.authRepository.findUniqueVerificationCode(
      {
        email_code_type: {
          email,
          code,
          type: type as PrismaVerificationCodeEnum
        }
      },
      client as any
    )

    if (!verificationCode) {
      throw InvalidOTPException
    }

    if (verificationCode.expiresAt < new Date()) {
      throw OTPExpiredException
    }

    return verificationCode
  }

  /**
   * Xác minh token OTP (token sau khi xác minh mã 6 số)
   * @param token Token OTP
   * @param email Email người dùng
   * @param type Loại mã xác thực
   * @param tokenType Loại token
   * @param deviceId ID thiết bị (tùy chọn)
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns VerificationToken nếu hợp lệ
   * @throws InvalidOTPTokenException, OTPTokenExpiredException, DeviceMismatchException
   */
  async validateVerificationToken({
    token,
    email,
    type,
    tokenType,
    deviceId,
    tx
  }: {
    token: string
    email: string
    type: TypeOfVerificationCodeType
    tokenType: TokenTypeType
    deviceId?: number
    tx?: PrismaTransactionClient
  }): Promise<PrismaVerificationToken> {
    const client = tx || this.prismaService

    const verificationToken = (await this.authRepository.findUniqueVerificationToken(
      { token },
      client as any
    )) as PrismaVerificationToken | null

    if (!verificationToken) {
      throw InvalidOTPTokenException
    }

    if (
      verificationToken.email !== email ||
      (verificationToken.type as string) !== type ||
      verificationToken.tokenType !== tokenType
    ) {
      throw InvalidOTPTokenException
    }

    if (verificationToken.expiresAt < new Date()) {
      throw OTPTokenExpiredException
    }

    if (deviceId !== undefined && verificationToken.deviceId !== undefined && deviceId !== verificationToken.deviceId) {
      throw DeviceMismatchException
    }

    return verificationToken
  }

  /**
   * Gửi mã OTP 6 số qua email
   * @param email Email người dùng
   * @param type Loại mã xác thực
   * @returns Kết quả gửi email
   * @throws FailedToSendOTPException
   */
  async sendOTP(email: string, type: TypeOfVerificationCodeType): Promise<{ message: string }> {
    // Trước tiên, xóa các mã cũ
    await this.authRepository.deleteVerificationCodesByEmailAndType({
      email,
      type
    })

    // Tạo mã OTP mới
    const code = generateOTP()

    // Lưu mã OTP vào database
    await this.authRepository.createVerificationCode({
      email,
      code,
      type,
      expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_TOKEN_EXPIRES_IN))
    })

    // Gửi OTP qua email
    const { error } = await this.emailService.sendOTP({
      email,
      code
    })

    if (error) {
      this.logger.error(`Failed to send OTP to ${email}`, error)
      throw FailedToSendOTPException
    }

    return { message: 'Auth.Otp.SentSuccessfully' }
  }

  /**
   * Tạo token OTP sau khi xác minh mã 6 số thành công
   * @param email Email người dùng
   * @param type Loại mã xác thực
   * @param userId ID người dùng (tùy chọn)
   * @param deviceId ID thiết bị (tùy chọn)
   * @param metadata Thông tin bổ sung (tùy chọn)
   * @param tx Client transaction Prisma (bắt buộc)
   * @returns Token OTP
   */
  async createOtpToken({
    email,
    type,
    userId,
    deviceId,
    metadata,
    tx
  }: {
    email: string
    type: TypeOfVerificationCodeType
    userId?: number
    deviceId?: number
    metadata?: Record<string, any>
    tx: PrismaTransactionClient
  }): Promise<string> {
    // Xóa các token OTP cũ
    await this.authRepository.deleteVerificationTokenByEmailAndType(email, type, TokenType.OTP, tx)

    // Tạo token OTP mới
    const token = uuidv4()

    await this.authRepository.createVerificationToken(
      {
        token,
        email,
        type,
        tokenType: TokenType.OTP,
        userId,
        deviceId,
        metadata: metadata ? JSON.stringify(metadata) : undefined,
        expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_TOKEN_EXPIRES_IN))
      },
      tx
    )

    return token
  }

  /**
   * Xóa token OTP
   * @param token Token OTP cần xóa
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Kết quả xóa token
   */
  async deleteOtpToken(token: string, tx?: PrismaTransactionClient): Promise<void> {
    const client = tx || this.prismaService
    await this.authRepository.deleteVerificationToken({ token }, client as any)
  }

  /**
   * Xóa mã xác thực 6 số
   * @param email Email người dùng
   * @param code Mã xác thực 6 số
   * @param type Loại mã xác thực
   * @param tx Client transaction Prisma (tùy chọn)
   */
  async deleteVerificationCode(
    email: string,
    code: string,
    type: TypeOfVerificationCodeType,
    tx?: PrismaTransactionClient
  ): Promise<void> {
    const client = tx || this.prismaService
    await this.authRepository.deleteVerificationCode(
      {
        email_code_type: {
          email,
          code,
          type: type as PrismaVerificationCodeEnum
        }
      },
      client as any
    )
  }

  /**
   * Xác minh mã OTP và tạo token OTP
   * @param payload Thông tin cần xác minh (email, code, type, userAgent, ip)
   * @param tx Client transaction Prisma (bắt buộc)
   * @returns Token OTP
   */
  async verifyOTPAndCreateToken(
    payload: {
      email: string
      code: string
      type: TypeOfVerificationCodeType
      userAgent?: string
      ip?: string
    },
    tx: PrismaTransactionClient,
    userId?: number
  ): Promise<string> {
    // Xác minh mã OTP
    await this.validateVerificationCode({
      email: payload.email,
      code: payload.code,
      type: payload.type,
      tx
    })

    // Tạo token OTP
    const token = await this.createOtpToken({
      email: payload.email,
      type: payload.type,
      userId,
      // deviceId được thêm bởi lớp gọi sau khi tạo hoặc tìm thiết bị
      tx
    })

    // Xóa mã OTP đã sử dụng
    await this.deleteVerificationCode(payload.email, payload.code, payload.type, tx)

    return token
  }

  /**
   * Chỉ tìm kiếm token xác thực mà không thực hiện validate (hữu ích cho việc lấy thông tin token trước khi validate)
   * @param token Token cần tìm
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Token xác thực nếu tìm thấy, null nếu không
   */
  async findVerificationToken(token: string, tx?: PrismaTransactionClient): Promise<PrismaVerificationToken | null> {
    const client = tx || this.prismaService
    return (await this.authRepository.findUniqueVerificationToken(
      { token },
      client as any
    )) as PrismaVerificationToken | null
  }
}
