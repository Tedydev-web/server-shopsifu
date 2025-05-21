import { Injectable, Logger } from '@nestjs/common'
import * as OTPAuth from 'otpauth'
import envConfig from 'src/shared/config'
import { PrismaService } from './prisma.service'
import { Prisma, PrismaClient, RecoveryCode } from '@prisma/client'
import { HashingService } from './hashing.service'
import { TwoFactorMethodTypeType } from 'src/shared/constants/auth.constant'
import { InvalidRecoveryCodeException } from 'src/routes/auth/auth.error'

type PrismaTransactionClient = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name)

  constructor(
    private readonly prismaService: PrismaService,
    private readonly hashingService: HashingService
  ) {}

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

  generateTOTPSecret(email: string) {
    this.logger.debug(`Generating TOTP secret for user: ${email}`)
    const totp = this.createTOTP(email)
    return {
      secret: totp.secret.base32,
      uri: totp.toString()
    }
  }

  verifyTOTP({ email, token, secret }: { email: string; secret: string; token: string }): boolean {
    this.logger.debug(`Verifying TOTP for user: ${email}`)
    const totp = this.createTOTP(email, secret)
    const delta = totp.validate({ token, window: 1 })
    return delta !== null
  }

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

  async verifyRecoveryCode(userId: number, recoveryCodeInput: string, tx?: PrismaTransactionClient) {
    this.logger.debug(`Verifying recovery code for user ${userId}`)
    const client = tx || this.prismaService

    const recoveryCodes = await client.recoveryCode.findMany({
      where: {
        userId: userId,
        used: false
      }
    })

    if (!recoveryCodes || recoveryCodes.length === 0) {
      this.logger.warn(`No recovery codes found for user ${userId}`)
      throw InvalidRecoveryCodeException
    }

    let matchedCodeEntry: RecoveryCode | null = null
    for (const rcEntry of recoveryCodes) {
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

  async getUnusedRecoveryCodes(userId: number, tx?: PrismaTransactionClient) {
    this.logger.debug(`Getting unused recovery codes for user ${userId}`)
    const client = tx || this.prismaService

    return client.recoveryCode.findMany({
      where: {
        userId: userId,
        used: false
      }
    })
  }

  async deleteAllRecoveryCodes(userId: number, tx?: PrismaTransactionClient) {
    this.logger.debug(`Deleting all recovery codes for user ${userId}`)
    const client = tx || this.prismaService

    return client.recoveryCode.deleteMany({
      where: { userId: userId }
    })
  }

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
      } as any
    })
  }

  async getUserTwoFactorStatus(userId: number, tx?: PrismaTransactionClient) {
    this.logger.debug(`Getting 2FA status for user ${userId}`)
    const client = tx || this.prismaService

    const user = await client.user.findUnique({
      where: { id: userId }
    })

    if (!user) return null

    return {
      twoFactorEnabled: user.twoFactorEnabled || false,
      twoFactorMethod: user.twoFactorMethod,
      twoFactorVerifiedAt: user.twoFactorVerifiedAt
    }
  }
}
