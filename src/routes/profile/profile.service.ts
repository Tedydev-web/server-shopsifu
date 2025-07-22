import { Injectable } from '@nestjs/common'
import { InvalidPasswordException, NotFoundRecordException } from 'src/shared/error'
import { ChangePasswordBodyType, UpdateMeBodyType } from './profile.model'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Injectable()
export class ProfileService {
  constructor(
    private readonly sharedUserRepository: SharedUserRepository,
    private readonly hashingService: HashingService,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async getProfile(user: AccessTokenPayload) {
    const userData = await this.sharedUserRepository.findUniqueIncludeRolePermissions({
      id: user.userId
    })

    if (!userData) {
      throw NotFoundRecordException
    }

    return {
      message: this.i18n.t('profile.success.GET_PROFILE'),
      data: userData
    }
  }

  async updateProfile({ user, body }: { user: AccessTokenPayload; body: UpdateMeBodyType }) {
    try {
      const userData = await this.sharedUserRepository.update(
        { id: user.userId },
        {
          ...body,
          updatedById: user.userId
        }
      )
      return {
        message: this.i18n.t('profile.success.UPDATE_PROFILE'),
        data: userData
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async changePassword({
    user,
    body
  }: {
    user: AccessTokenPayload
    body: Omit<ChangePasswordBodyType, 'confirmNewPassword'>
  }) {
    try {
      const { password, newPassword } = body
      const userData = await this.sharedUserRepository.findUnique({
        id: user.userId
      })
      if (!userData) {
        throw NotFoundRecordException
      }
      const isPasswordMatch = await this.hashingService.compare(password, userData.password)
      if (!isPasswordMatch) {
        throw InvalidPasswordException
      }
      const hashedPassword = await this.hashingService.hash(newPassword)

      await this.sharedUserRepository.update(
        { id: user.userId },
        {
          password: hashedPassword,
          updatedById: user.userId
        }
      )
      return {
        message: this.i18n.t('profile.success.CHANGE_PASSWORD')
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
