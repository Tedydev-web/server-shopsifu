import { Injectable } from '@nestjs/common'
import { LanguageRepo } from 'src/routes/language/language.repo'
import { CreateLanguageBodyType, UpdateLanguageBodyType } from 'src/routes/language/language.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { LanguageAlreadyExistsException } from 'src/routes/language/language.error'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class LanguageService {
  constructor(
    private languageRepo: LanguageRepo,
    private i18n: I18nService<I18nTranslations>
  ) {}

  async findAll() {
    const data = await this.languageRepo.findAll()
    return {
      message: this.i18n.t('language.language.success.GET_SUCCESS'),
      data,
      totalItems: data.length
    }
  }

  async findById(id: string) {
    const language = await this.languageRepo.findById(id)
    if (!language) {
      throw NotFoundRecordException
    }
    return {
      message: this.i18n.t('language.language.success.GET_DETAIL_SUCCESS'),
      data: language
    }
  }

  async create({ data, createdById }: { data: CreateLanguageBodyType; createdById: string }) {
    try {
      const language = await this.languageRepo.create({
        createdById,
        data
      })
      return {
        message: this.i18n.t('language.language.success.CREATE_SUCCESS'),
        data: language
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw LanguageAlreadyExistsException
      }
      throw error
    }
  }

  async update({ id, data, updatedById }: { id: string; data: UpdateLanguageBodyType; updatedById: string }) {
    try {
      const language = await this.languageRepo.update({
        id,
        updatedById,
        data
      })
      return {
        message: this.i18n.t('language.language.success.UPDATE_SUCCESS'),
        data: language
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete(id: string) {
    try {
      // hard delete
      await this.languageRepo.delete(id, true)
      return {
        message: this.i18n.t('language.language.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
