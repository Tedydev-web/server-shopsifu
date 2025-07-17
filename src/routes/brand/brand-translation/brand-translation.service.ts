import { Injectable } from '@nestjs/common'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { BrandTranslationRepo } from 'src/routes/brand/brand-translation/brand-translation.repo'
import { BrandTranslationAlreadyExistsException } from 'src/routes/brand/brand-translation/brand-translation.error'
import {
  CreateBrandTranslationBodyType,
  UpdateBrandTranslationBodyType
} from 'src/routes/brand/brand-translation/brand-translation.model'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class BrandTranslationService {
  constructor(
    private brandTranslationRepo: BrandTranslationRepo,
    private i18n: I18nService<I18nTranslations>
  ) {}

  async findById(id: string) {
    const brand = await this.brandTranslationRepo.findById(id)
    if (!brand) {
      throw NotFoundRecordException
    }
    return {
      message: this.i18n.t('brand.brandTranslation.success.GET_DETAIL_SUCCESS'),
      data: brand
    }
  }

  async create({ data, createdById }: { data: CreateBrandTranslationBodyType; createdById: string }) {
    try {
      const brand = await this.brandTranslationRepo.create({
        createdById,
        data
      })
      return {
        message: this.i18n.t('brand.brandTranslation.success.CREATE_SUCCESS'),
        data: brand
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw BrandTranslationAlreadyExistsException
      }
      throw error
    }
  }

  async update({ id, data, updatedById }: { id: string; data: UpdateBrandTranslationBodyType; updatedById: string }) {
    try {
      const brand = await this.brandTranslationRepo.update({
        id,
        updatedById,
        data
      })
      return {
        message: this.i18n.t('brand.brandTranslation.success.UPDATE_SUCCESS'),
        data: brand
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw BrandTranslationAlreadyExistsException
      }
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: string; deletedById: string }) {
    try {
      await this.brandTranslationRepo.delete({
        id,
        deletedById
      })
      return {
        message: this.i18n.t('brand.brandTranslation.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
