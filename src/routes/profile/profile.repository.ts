import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma } from '@prisma/client'

@Injectable()
export class ProfileRepository {
  private readonly logger = new Logger(ProfileRepository.name)

  constructor(private readonly prismaService: PrismaService) {}

  async findByUserId(userId: number, select?: Prisma.UserProfileSelect) {
    return this.prismaService.userProfile.findUnique({
      where: { userId },
      select
    })
  }

  async updateByUserId(userId: number, data: Prisma.UserProfileUpdateInput) {
    return this.prismaService.userProfile.update({
      where: { userId },
      data
    })
  }

  async doesUsernameExist(username: string): Promise<boolean> {
    const count = await this.prismaService.userProfile.count({
      where: { username }
    })
    return count > 0
  }

  async doesPhoneNumberExist(phoneNumber: string): Promise<boolean> {
    const count = await this.prismaService.userProfile.count({
      where: { phoneNumber }
    })
    return count > 0
  }
}
