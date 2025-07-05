import { Injectable } from '@nestjs/common'
import {
  isNotFoundPrismaError,
  isUniqueConstraintPrismaError,
  isForeignKeyConstraintPrismaError,
  isForeignKeyConstraintForConstraint,
} from 'src/shared/helpers'
import { CategoryTranslationRepo } from 'src/routes/category/category-translation/category-translation.repo'
import {
  CategoryTranslationAlreadyExistsException,
  CategoryTranslationLanguageNotFoundException,
  CategoryTranslationCategoryNotFoundException,
} from 'src/routes/category/category-translation/category-translation.error'
import {
  CreateCategoryTranslationBodyType,
  UpdateCategoryTranslationBodyType,
} from 'src/routes/category/category-translation/category-translation.model'
import { NotFoundRecordException } from 'src/shared/error'

@Injectable()
export class CategoryTranslationService {
  constructor(private categoryTranslationRepo: CategoryTranslationRepo) {}

  async findById(id: number) {
    const category = await this.categoryTranslationRepo.findById(id)
    if (!category) {
      throw NotFoundRecordException
    }
    return category
  }

  async create({ data, createdById }: { data: CreateCategoryTranslationBodyType; createdById: number }) {
    try {
      return await this.categoryTranslationRepo.create({
        createdById,
        data,
      })
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw CategoryTranslationAlreadyExistsException
      }
      if (isForeignKeyConstraintForConstraint(error, 'CategoryTranslation_languageId_fkey')) {
        throw CategoryTranslationLanguageNotFoundException
      }
      if (isForeignKeyConstraintForConstraint(error, 'CategoryTranslation_categoryId_fkey')) {
        throw CategoryTranslationCategoryNotFoundException
      }
      throw error
    }
  }

  async update({
    id,
    data,
    updatedById,
  }: {
    id: number
    data: UpdateCategoryTranslationBodyType
    updatedById: number
  }) {
    try {
      const category = await this.categoryTranslationRepo.update({
        id,
        updatedById,
        data,
      })
      return category
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw CategoryTranslationAlreadyExistsException
      }
      if (isForeignKeyConstraintForConstraint(error, 'CategoryTranslation_languageId_fkey')) {
        throw CategoryTranslationLanguageNotFoundException
      }
      if (isForeignKeyConstraintForConstraint(error, 'CategoryTranslation_categoryId_fkey')) {
        throw CategoryTranslationCategoryNotFoundException
      }
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: number; deletedById: number }) {
    try {
      await this.categoryTranslationRepo.delete({
        id,
        deletedById,
      })
      return {
        message: 'Delete successfully',
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
