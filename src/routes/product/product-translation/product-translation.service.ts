import { Injectable } from '@nestjs/common'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { ProductTranslationRepo } from 'src/routes/product/product-translation/product-translation.repo'
import { ProductTranslationAlreadyExistsException } from 'src/routes/product/product-translation/product-translation.error'
import {
  CreateProductTranslationBodyType,
  UpdateProductTranslationBodyType
} from 'src/routes/product/product-translation/product-translation.model'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class ProductTranslationService {
  constructor(
    private productTranslationRepo: ProductTranslationRepo,
    private i18n: I18nService<I18nTranslations>
  ) {}

  async findById(id: string) {
    const product = await this.productTranslationRepo.findById(id)
    if (!product) {
      throw NotFoundRecordException
    }
    return {
      message: this.i18n.t('product.productTranslation.success.GET_DETAIL_SUCCESS'),
      data: product
    }
  }

  async create({ data, createdById }: { data: CreateProductTranslationBodyType; createdById: string }) {
    try {
      return await this.productTranslationRepo.create({
        createdById,
        data
      })
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw ProductTranslationAlreadyExistsException
      }
      throw error
    }
  }

  async update({ id, data, updatedById }: { id: string; data: UpdateProductTranslationBodyType; updatedById: string }) {
    try {
      const product = await this.productTranslationRepo.update({
        id,
        updatedById,
        data
      })
      return {
        message: this.i18n.t('product.productTranslation.success.UPDATE_SUCCESS'),
        data: product
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw ProductTranslationAlreadyExistsException
      }
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: string; deletedById: string }) {
    try {
      await this.productTranslationRepo.delete({
        id,
        deletedById
      })
      return {
        message: this.i18n.t('product.productTranslation.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
