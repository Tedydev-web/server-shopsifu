import { Injectable } from '@nestjs/common'
import { VerificationCodeType } from '../model/auth.model'
import { TypeOfVerificationCodeType } from 'src/shared/constants/auth.constant'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class VerificationCodeRepository {
  constructor(private readonly prisma: PrismaService) {}

  async create(
    payload: Pick<VerificationCodeType, 'email' | 'type' | 'code' | 'expiresAt'>
  ): Promise<VerificationCodeType> {
    return this.prisma.verificationCode.create({
      data: payload
    })
  }

  async findUnique(uniqueValue: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
  }): Promise<VerificationCodeType | null> {
    return this.prisma.verificationCode.findUnique({
      where: {
        email_code_type: uniqueValue
      }
    })
  }

  async delete(uniqueValue: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
  }): Promise<VerificationCodeType> {
    return this.prisma.verificationCode.delete({
      where: {
        email_code_type: uniqueValue
      }
    })
  }
}
