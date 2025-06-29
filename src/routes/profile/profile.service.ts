import { Injectable } from '@nestjs/common'
import { ChangePasswordBodyType, UpdateMeBodySchema, UpdateMeBodyType } from './profile.model'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { isUniqueConstraintPrismaError } from 'src/shared/utils/prisma.utils'
import { GlobalError } from 'src/shared/global.error'

@Injectable()
export class ProfileService {
  constructor(
    private readonly sharedUserRepository: SharedUserRepository,
    private readonly hashingService: HashingService,
  ) {}

  async getProfile(userId: number) {
    const user = await this.sharedUserRepository.findUniqueIncludeRolePermissions({
      id: userId,
      deletedAt: null,
    })

    if (!user) {
      throw GlobalError.NotFoundRecordException()
    }

    return user
  }

  async updateProfile({ userId, body }: { userId: number; body: UpdateMeBodyType }) {
    try {
      return await this.sharedUserRepository.update(
        { id: userId, deletedAt: null },
        {
          ...body,
          updatedById: userId,
        },
      )
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw GlobalError.NotFoundRecordException()
      }
      throw error
    }
  }

  async changePassword({ userId, body }: { userId: number; body: Omit<ChangePasswordBodyType, 'confirmNewPassword'> }) {
    try {
      const { password, newPassword } = body
      const user = await this.sharedUserRepository.findUnique({
        id: userId,
        deletedAt: null,
      })
      if (!user) {
        throw GlobalError.NotFoundRecordException()
      }
      const isPasswordMatch = await this.hashingService.compare(password, user.password)
      if (!isPasswordMatch) {
        throw GlobalError.InvalidPasswordException()
      }
      const hashedPassword = await this.hashingService.hash(newPassword)

      await this.sharedUserRepository.update(
        { id: userId, deletedAt: null },
        {
          password: hashedPassword,
          updatedById: userId,
        },
      )
      return {
        message: 'Password changed successfully',
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw GlobalError.NotFoundRecordException()
      }
      throw error
    }
  }
}
