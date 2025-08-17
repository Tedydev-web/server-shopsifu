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
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

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

  async create({ data, user }: { data: CreateProductTranslationBodyType; user: AccessTokenPayload }) {
    try {
      return await this.productTranslationRepo.create({
        createdById: user.userId,
        data
      })
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw ProductTranslationAlreadyExistsException
      }
      throw error
    }
  }

  async update({ id, data, user }: { id: string; data: UpdateProductTranslationBodyType; user: AccessTokenPayload }) {
    try {
      const product = await this.productTranslationRepo.update({
        id,
        updatedById: user.userId,
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

  async delete({ id, user }: { id: string; user: AccessTokenPayload }) {
    try {
      await this.productTranslationRepo.delete({
        id,
        deletedById: user.userId
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
