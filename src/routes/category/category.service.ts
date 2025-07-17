import { Injectable } from '@nestjs/common'
import { CategoryRepo } from 'src/routes/category/category.repo'
import { CreateCategoryBodyType, UpdateCategoryBodyType } from 'src/routes/category/category.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { I18nContext } from 'nestjs-i18n'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class CategoryService {
  constructor(
    private categoryRepo: CategoryRepo,
    private i18n: I18nService<I18nTranslations>
  ) {}

  async findAll(parentCategoryId?: string | null) {
    const data = await this.categoryRepo.findAll({
      parentCategoryId,
      languageId: I18nContext.current()?.lang as string
    })
    return {
      message: this.i18n.t('category.category.success.GET_SUCCESS'),
      data: data.data,
      totalItems: data.totalItems
    }
  }

  async findById(id: string) {
    const category = await this.categoryRepo.findById({
      id,
      languageId: I18nContext.current()?.lang as string
    })
    if (!category) {
      throw NotFoundRecordException
    }
    return {
      message: this.i18n.t('category.category.success.GET_DETAIL_SUCCESS'),
      data: category
    }
  }

  async create({ data, createdById }: { data: CreateCategoryBodyType; createdById: string }) {
    const category = await this.categoryRepo.create({
      createdById,
      data
    })
    return {
      message: this.i18n.t('category.category.success.CREATE_SUCCESS'),
      data: category
    }
  }

  async update({ id, data, updatedById }: { id: string; data: UpdateCategoryBodyType; updatedById: string }) {
    try {
      const category = await this.categoryRepo.update({
        id,
        updatedById,
        data
      })
      return {
        message: this.i18n.t('category.category.success.UPDATE_SUCCESS'),
        data: category
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: string; deletedById: string }) {
    try {
      await this.categoryRepo.delete({
        id,
        deletedById
      })
      return {
        message: this.i18n.t('category.category.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
