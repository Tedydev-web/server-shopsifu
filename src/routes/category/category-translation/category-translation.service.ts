import { Injectable } from '@nestjs/common'
import { NotFoundRecordException } from 'src/shared/error'
import {
  isNotFoundPrismaError,
  isUniqueConstraintPrismaError,
  isForeignKeyConstraintPrismaError
} from 'src/shared/helpers'
import { CategoryTranslationRepo } from 'src/routes/category/category-translation/category-translation.repo'
import { CategoryTranslationAlreadyExistsException } from 'src/routes/category/category-translation/category-translation.error'
import {
  CreateCategoryTranslationBodyType,
  UpdateCategoryTranslationBodyType
} from 'src/routes/category/category-translation/category-translation.model'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'

@Injectable()
export class CategoryTranslationService {
  constructor(
    private categoryTranslationRepo: CategoryTranslationRepo,
    private i18n: I18nService<I18nTranslations>
  ) {}

  async findById(id: number) {
    const category = await this.categoryTranslationRepo.findById(id)
    if (!category) {
      throw NotFoundRecordException
    }

    return {
      data: category,
      message: this.i18n.t('category.categoryTranslation.success.GET_DETAIL_SUCCESS')
    }
  }

  async create({ data, createdById }: { data: CreateCategoryTranslationBodyType; createdById: number }) {
    try {
      const categoryTranslation = await this.categoryTranslationRepo.create({
        createdById,
        data
      })

      return {
        data: categoryTranslation,
        message: this.i18n.t('category.categoryTranslation.success.CREATE_SUCCESS')
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw CategoryTranslationAlreadyExistsException
      }
      if (isForeignKeyConstraintPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async update({
    id,
    data,
    updatedById
  }: {
    id: number
    data: UpdateCategoryTranslationBodyType
    updatedById: number
  }) {
    try {
      const category = await this.categoryTranslationRepo.update({
        id,
        updatedById,
        data
      })

      return {
        data: category,
        message: this.i18n.t('category.categoryTranslation.success.UPDATE_SUCCESS')
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw CategoryTranslationAlreadyExistsException
      }
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      if (isForeignKeyConstraintPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: number; deletedById: number }) {
    try {
      await this.categoryTranslationRepo.delete({
        id,
        deletedById
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
