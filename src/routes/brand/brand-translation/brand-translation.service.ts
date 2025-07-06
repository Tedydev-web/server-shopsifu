import { Injectable } from '@nestjs/common'
import { NotFoundRecordException } from 'src/shared/error'
import {
  isNotFoundPrismaError,
  isUniqueConstraintPrismaError,
  isForeignKeyConstraintPrismaError
} from 'src/shared/helpers'
import { BrandTranslationRepo } from 'src/routes/brand/brand-translation/brand-translation.repo'
import {
  BrandTranslationAlreadyExistsException,
  BrandTranslationBrandNotFoundException,
  BrandTranslationLanguageNotFoundException
} from 'src/routes/brand/brand-translation/brand-translation.error'
import {
  CreateBrandTranslationBodyType,
  UpdateBrandTranslationBodyType
} from 'src/routes/brand/brand-translation/brand-translation.model'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'

@Injectable()
export class BrandTranslationService {
  constructor(
    private brandTranslationRepo: BrandTranslationRepo,
    private i18n: I18nService
  ) {}

  async findById(id: number) {
    const brand = await this.brandTranslationRepo.findById(id)
    if (!brand) {
      throw NotFoundRecordException
    }

    return {
      data: brand,
      message: this.i18n.t('brand.brandTranslation.success.GET_DETAIL_SUCCESS')
    }
  }

  async create({ data, createdById }: { data: CreateBrandTranslationBodyType; createdById: number }) {
    try {
      const brandTranslation = await this.brandTranslationRepo.create({
        createdById,
        data
      })

      return {
        data: brandTranslation,
        message: this.i18n.t('brand.brandTranslation.success.CREATE_SUCCESS')
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw BrandTranslationAlreadyExistsException
      }
      if (isForeignKeyConstraintPrismaError(error)) {
        const constraint = error.meta?.constraint as string
        if (constraint?.includes('brandId')) {
          throw BrandTranslationBrandNotFoundException
        }
        if (constraint?.includes('languageId')) {
          throw BrandTranslationLanguageNotFoundException
        }
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async update({ id, data, updatedById }: { id: number; data: UpdateBrandTranslationBodyType; updatedById: number }) {
    try {
      const brand = await this.brandTranslationRepo.update({
        id,
        updatedById,
        data
      })

      return {
        data: brand,
        message: this.i18n.t('brand.brandTranslation.success.UPDATE_SUCCESS')
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw BrandTranslationAlreadyExistsException
      }
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      if (isForeignKeyConstraintPrismaError(error)) {
        const constraint = error.meta?.constraint as string
        if (constraint?.includes('brandId')) {
          throw BrandTranslationBrandNotFoundException
        }
        if (constraint?.includes('languageId')) {
          throw BrandTranslationLanguageNotFoundException
        }
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: number; deletedById: number }) {
    try {
      await this.brandTranslationRepo.delete({
        id,
        deletedById
      })
      return {
        message: this.i18n.t('brand.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
