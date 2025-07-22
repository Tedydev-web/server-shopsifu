import { Injectable } from '@nestjs/common'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { CategoryTranslationRepo } from 'src/routes/category/category-translation/category-translation.repo'
import { CategoryTranslationAlreadyExistsException } from 'src/routes/category/category-translation/category-translation.error'
import {
  CreateCategoryTranslationBodyType,
  UpdateCategoryTranslationBodyType
} from 'src/routes/category/category-translation/category-translation.model'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Injectable()
export class CategoryTranslationService {
  constructor(
    private categoryTranslationRepo: CategoryTranslationRepo,
    private i18n: I18nService<I18nTranslations>
  ) {}

  async findById(id: string) {
    const category = await this.categoryTranslationRepo.findById(id)
    if (!category) {
      throw NotFoundRecordException
    }
    return {
      message: this.i18n.t('category.categoryTranslation.success.GET_DETAIL_SUCCESS'),
      data: category.data
    }
  }

  async create({ data, user }: { data: CreateCategoryTranslationBodyType; user: AccessTokenPayload }) {
    try {
      const category = await this.categoryTranslationRepo.create({
        createdById: user.userId,
        data
      })
      return {
        message: this.i18n.t('category.categoryTranslation.success.CREATE_SUCCESS'),
        data: category
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw CategoryTranslationAlreadyExistsException
      }
      throw error
    }
  }

  async update({ id, data, user }: { id: string; data: UpdateCategoryTranslationBodyType; user: AccessTokenPayload }) {
    try {
      const category = await this.categoryTranslationRepo.update({
        id,
        updatedById: user.userId,
        data
      })
      return {
        message: this.i18n.t('category.categoryTranslation.success.UPDATE_SUCCESS'),
        data: category
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw CategoryTranslationAlreadyExistsException
      }
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete({ id, user }: { id: string; user: AccessTokenPayload }) {
    try {
      await this.categoryTranslationRepo.delete({
        id,
        deletedById: user.userId
      })
      return {
        message: this.i18n.t('category.categoryTranslation.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
