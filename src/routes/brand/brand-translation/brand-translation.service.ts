import { Injectable } from '@nestjs/common'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { BrandTranslationRepo } from 'src/routes/brand/brand-translation/brand-translation.repo'
import { BrandTranslationAlreadyExistsException } from 'src/routes/brand/brand-translation/brand-translation.error'
import {
  CreateBrandTranslationBodyType,
  UpdateBrandTranslationBodyType,
} from 'src/routes/brand/brand-translation/brand-translation.model'

@Injectable()
export class BrandTranslationService {
  constructor(private brandTranslationRepo: BrandTranslationRepo) {}

  async findById(id: number) {
    const brand = await this.brandTranslationRepo.findById(id)
    if (!brand) {
      throw NotFoundRecordException
    }
    return brand
  }

  async create({ data, createdById }: { data: CreateBrandTranslationBodyType; createdById: number }) {
    try {
      return await this.brandTranslationRepo.create({
        createdById,
        data,
      })
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw BrandTranslationAlreadyExistsException
      }
      throw error
    }
  }

  async update({ id, data, updatedById }: { id: number; data: UpdateBrandTranslationBodyType; updatedById: number }) {
    try {
      const brand = await this.brandTranslationRepo.update({
        id,
        updatedById,
        data,
      })
      return brand
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

  async delete({ id, deletedById }: { id: number; deletedById: number }) {
    try {
      await this.brandTranslationRepo.delete({
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
