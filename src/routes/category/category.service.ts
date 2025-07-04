import { Injectable } from '@nestjs/common'
import { CategoryRepo } from 'src/routes/category/category.repo'
import {
  CreateCategoryBodyType,
  UpdateCategoryBodyType,
  GetAllCategoriesQueryType,
} from 'src/routes/category/category.model'
import { ExceptionFactory } from 'src/shared/error'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { I18nContext } from 'nestjs-i18n'

@Injectable()
export class CategoryService {
  constructor(private categoryRepo: CategoryRepo) {}

  findAll(query: GetAllCategoriesQueryType) {
    return this.categoryRepo.findAll({
      ...query,
      languageId: I18nContext.current()?.lang as string,
    })
  }

  async findById(id: number) {
    const category = await this.categoryRepo.findById({
      id,
      languageId: I18nContext.current()?.lang as string,
    })
    if (!category) {
      throw ExceptionFactory.recordNotFound()
    }
    return category
  }

  create({ data, createdById }: { data: CreateCategoryBodyType; createdById: number }) {
    return this.categoryRepo.create({
      createdById,
      data,
    })
  }

  async update({ id, data, updatedById }: { id: number; data: UpdateCategoryBodyType; updatedById: number }) {
    try {
      const category = await this.categoryRepo.update({
        id,
        updatedById,
        data,
      })
      return category
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw ExceptionFactory.recordNotFound()
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: number; deletedById: number }) {
    try {
      await this.categoryRepo.delete({
        id,
        deletedById,
      })
      return {
        message: 'Delete successfully',
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw ExceptionFactory.recordNotFound()
      }
      throw error
    }
  }
}
