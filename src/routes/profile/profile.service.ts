import { Injectable } from '@nestjs/common'
import { ChangePasswordBodyType, UpdateMeBodyType } from './profile.model'
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

    if (!user || !user.role || user.role.deletedAt !== null) {
      throw GlobalError.Forbidden('profile.error.ROLE_NOT_FOUND_OR_INACTIVE')
    }

    if (!user.role.permissions) {
      user.role.permissions = []
    }

    return user
  }

  async updateProfile({ userId, body }: { userId: number; body: UpdateMeBodyType }) {
    try {
      return await this.sharedUserRepository.updateByCondition(
        { id: userId },
        {
          ...body,
          updatedById: userId,
        },
      )
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw GlobalError.NotFound('profile.error.NOT_FOUND')
      }
      throw error
    }
  }

  async changePassword({ userId, body }: { userId: number; body: Omit<ChangePasswordBodyType, 'confirmNewPassword'> }) {
    try {
      const { password, newPassword } = body
      const user = await this.sharedUserRepository.findById(userId)
      if (!user) {
        throw GlobalError.NotFound('profile.error.NOT_FOUND')
      }
      const isPasswordMatch = await this.hashingService.compare(password, user.password)
      if (!isPasswordMatch) {
        throw GlobalError.InvalidPassword('profile.error.INVALID_PASSWORD')
      }
      const hashedPassword = await this.hashingService.hash(newPassword)

      await this.sharedUserRepository.updateByCondition(
        { id: userId },
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
        throw GlobalError.NotFound('profile.error.NOT_FOUND')
      }
      throw error
    }
  }
}
