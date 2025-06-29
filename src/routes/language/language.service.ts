import { Injectable } from '@nestjs/common'
import { LanguageRepo } from 'src/routes/language/language.repo'
import {
  CreateLanguageBodyType,
  UpdateLanguageBodyType,
  LanguageType,
  LanguagePaginationQueryType,
  PaginatedResponseType,
} from 'src/routes/language/language.model'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/utils/prisma.utils'
import { LanguageError } from 'src/routes/language/language.error'

@Injectable()
export class LanguageService {
  constructor(private languageRepo: LanguageRepo) {}

  // Standard offset-based pagination for admin/management UI
  async findAll(query: LanguagePaginationQueryType): Promise<PaginatedResponseType<LanguageType>> {
    try {
      return await this.languageRepo.findAllWithPagination(query)
    } catch (error) {
      throw LanguageError.OperationFailed
    }
  }

  async findById(id: string): Promise<LanguageType> {
    try {
      const language = await this.languageRepo.findById(id)
      if (!language) {
        throw LanguageError.NotFound
      }
      return language
    } catch (error) {
      if (error === LanguageError.NotFound) {
        throw error
      }
      throw LanguageError.OperationFailed
    }
  }

  async create(body: CreateLanguageBodyType, userId: number): Promise<LanguageType> {
    // Kiểm tra language đã tồn tại chưa (theo id hoặc name)
    const existingLanguage = await this.languageRepo.findByIdOrName(body.id, body.name)
    if (existingLanguage) {
      throw LanguageError.AlreadyExists
    }

    try {
      const language = await this.languageRepo.create({
        data: body,
        createdById: userId,
      })
      return language
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw LanguageError.AlreadyExists
      }
      throw LanguageError.OperationFailed
    }
  }

  async update(id: string, body: UpdateLanguageBodyType, userId: number): Promise<LanguageType> {
    // Kiểm tra tên language đã tồn tại chưa (loại trừ chính nó)
    const existingLanguage = await this.languageRepo.findNameExcludingCurrent(body.name, id)
    if (existingLanguage) {
      throw LanguageError.AlreadyExists
    }

    try {
      const language = await this.languageRepo.update(id, { ...body, updatedById: userId })
      return language
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw LanguageError.NotFound
      }
      if (isUniqueConstraintPrismaError(error)) {
        throw LanguageError.AlreadyExists
      }
      throw LanguageError.OperationFailed
    }
  }

  async delete(id: string, userId: number): Promise<LanguageType> {
    try {
      const language = await this.languageRepo.delete(id, { deletedById: userId })
      return language
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw LanguageError.NotFound
      }
      throw LanguageError.OperationFailed
    }
  }
}
