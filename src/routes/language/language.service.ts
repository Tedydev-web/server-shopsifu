import { Injectable } from '@nestjs/common'
import { LanguageRepo } from 'src/routes/language/language.repo'
import { CreateLanguageBodyType, UpdateLanguageBodyType, LanguageType } from 'src/routes/language/language.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { LanguageAlreadyExistsException } from 'src/routes/language/language.error'

@Injectable()
export class LanguageService {
  constructor(private languageRepo: LanguageRepo) {}

  async findAll(): Promise<{ data: LanguageType[]; totalItems: number }> {
    const data = await this.languageRepo.findAll()
    return {
      data,
      totalItems: data.length
    }
  }

  async findById(id: string): Promise<LanguageType> {
    const language = await this.languageRepo.findById(id)
    if (!language) {
      throw NotFoundRecordException('Error.Language.NotFound', 'RESOURCE_NOT_FOUND', [
        { code: 'Error.Language.NotFound', args: { id } }
      ])
    }
    return language
  }

  async create({ data, createdById }: { data: CreateLanguageBodyType; createdById: number }): Promise<LanguageType> {
    try {
      const newLanguage = await this.languageRepo.create({
        createdById,
        data
      })
      return newLanguage
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw LanguageAlreadyExistsException
      }
      throw error
    }
  }

  async update({
    id,
    data,
    updatedById
  }: {
    id: string
    data: UpdateLanguageBodyType
    updatedById: number
  }): Promise<LanguageType> {
    try {
      const updatedLanguage = await this.languageRepo.update({
        id,
        updatedById,
        data
      })
      return updatedLanguage
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException('Error.Language.NotFoundOnUpdate', 'RESOURCE_NOT_FOUND', [
          { code: 'Error.Language.NotFoundOnUpdate', args: { id } }
        ])
      }
      throw error
    }
  }

  async delete(id: string): Promise<{ message: string }> {
    try {
      // hard delete
      await this.languageRepo.delete(id, true)
      return {
        message: 'Language.Delete.Success'
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException('Error.Language.NotFoundOnDelete', 'RESOURCE_NOT_FOUND', [
          { code: 'Error.Language.NotFoundOnDelete', args: { id } }
        ])
      }
      throw error
    }
  }
}
