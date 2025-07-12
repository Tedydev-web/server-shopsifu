import { Injectable } from '@nestjs/common'
import { BrandRepo } from 'src/routes/brand/brand.repo'
import { CreateBrandBodyType, UpdateBrandBodyType } from 'src/routes/brand/brand.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { PaginationQueryType } from 'src/shared/models/request.model'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { BrandAlreadyExistsException } from 'src/routes/brand/brand.error'

@Injectable()
export class BrandService {
  constructor(
    private brandRepo: BrandRepo,
    private i18n: I18nService<I18nTranslations>
  ) {}

  async list(pagination: PaginationQueryType) {
    const result = await this.brandRepo.list(pagination, I18nContext.current()?.lang as string)
    return {
      message: this.i18n.t('brand.brand.success.GET_SUCCESS'),
      data: result.data,
      metadata: result.metadata
    }
  }

  async findById(id: number) {
    const brand = await this.brandRepo.findById(id, I18nContext.current()?.lang as string)
    if (!brand) {
      throw NotFoundRecordException
    }
    return {
      message: this.i18n.t('brand.brand.success.GET_DETAIL_SUCCESS'),
      data: brand
    }
  }

  async create({ data, createdById }: { data: CreateBrandBodyType; createdById: number }) {
    try {
      const brand = await this.brandRepo.create({
        createdById,
        data
      })
      return {
        message: this.i18n.t('brand.brand.success.CREATE_SUCCESS'),
        data: brand
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw BrandAlreadyExistsException
      }
      throw error
    }
  }

  async update({ id, data, updatedById }: { id: number; data: UpdateBrandBodyType; updatedById: number }) {
    try {
      const brand = await this.brandRepo.update({
        id,
        updatedById,
        data
      })
      return {
        message: this.i18n.t('brand.brand.success.UPDATE_SUCCESS'),
        data: brand
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      if (isUniqueConstraintPrismaError(error)) {
        throw BrandAlreadyExistsException
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: number; deletedById: number }) {
    try {
      await this.brandRepo.delete({
        id,
        deletedById
      })
      return {
        message: this.i18n.t('brand.brand.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
