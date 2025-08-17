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
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

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
      data: brand.data // Lấy .data thay vì trả nguyên object
    }
  }

  async create({ data, user }: { data: CreateBrandTranslationBodyType; user: AccessTokenPayload }) {
    try {
      const brand = await this.brandTranslationRepo.create({
        createdById: user.userId,
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

  async update({ id, data, user }: { id: string; data: UpdateBrandTranslationBodyType; user: AccessTokenPayload }) {
    try {
      const brand = await this.brandTranslationRepo.update({
        id,
        updatedById: user.userId,
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

  async delete({ id, user }: { id: string; user: AccessTokenPayload }) {
    try {
      await this.brandTranslationRepo.delete({
        id,
        deletedById: user.userId
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
