import { Injectable, Logger } from '@nestjs/common'
import { TokenType, TokenTypeType, TypeOfVerificationCodeType } from '../constants/auth.constants'
import envConfig from 'src/shared/config'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { EmailService } from './email.service'
import { addMilliseconds } from 'date-fns'
import ms from 'ms'
import { v4 as uuidv4 } from 'uuid'
import { generateOTP } from 'src/routes/auth/utils/otp.utils'
import { PrismaService } from 'src/shared/services/prisma.service'
import {
  VerificationCode as PrismaVerificationCodeModel,
  VerificationToken as PrismaVerificationToken,
  VerificationCodeType as PrismaVerificationCodeEnum
} from '@prisma/client'
import {
  InvalidOTPException,
  OTPExpiredException,
  FailedToSendOTPException,
  InvalidOTPTokenException,
  OTPTokenExpiredException,
  DeviceMismatchException
} from 'src/routes/auth/auth.error'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'

@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name)

  constructor(
    private readonly prismaService: PrismaService,
    private readonly authRepository: AuthRepository,
    private readonly emailService: EmailService
  ) {}

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
      client
    )

    if (!verificationCode) {
      throw InvalidOTPException
    }

    if (verificationCode.expiresAt < new Date()) {
      throw OTPExpiredException
    }

    return verificationCode
  }

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

    const verificationToken = await this.authRepository.findUniqueVerificationToken({ token }, client)

    if (!verificationToken) {
      throw InvalidOTPTokenException
    }

    if (
      verificationToken.email !== email ||
      verificationToken.type !== (type as PrismaVerificationCodeEnum) ||
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

  async sendOTP(email: string, type: TypeOfVerificationCodeType): Promise<{ message: string }> {
    await this.authRepository.deleteVerificationCodesByEmailAndType({
      email,
      type
    })

    const code = generateOTP()

    await this.authRepository.createVerificationCode({
      email,
      code,
      type: type as PrismaVerificationCodeEnum,
      expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_TOKEN_EXPIRES_IN))
    })

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
    await this.authRepository.deleteVerificationTokenByEmailAndType(email, type, TokenType.OTP, tx)

    const token = uuidv4()

    await this.authRepository.createVerificationToken(
      {
        token,
        email,
        type: type as PrismaVerificationCodeEnum,
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

  async deleteOtpToken(token: string, tx?: PrismaTransactionClient): Promise<void> {
    const client = tx || this.prismaService
    await this.authRepository.deleteVerificationToken({ token }, client)
  }

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
      client
    )
  }

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
    await this.validateVerificationCode({
      email: payload.email,
      code: payload.code,
      type: payload.type,
      tx
    })

    const token = await this.createOtpToken({
      email: payload.email,
      type: payload.type,
      userId,
      tx
    })

    await this.deleteVerificationCode(payload.email, payload.code, payload.type, tx)

    return token
  }

  async findVerificationToken(token: string, tx?: PrismaTransactionClient): Promise<PrismaVerificationToken | null> {
    const client = tx || this.prismaService
    return await this.authRepository.findUniqueVerificationToken({ token }, client)
  }
}
