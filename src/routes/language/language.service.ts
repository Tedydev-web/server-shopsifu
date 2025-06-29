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
import { GlobalError } from 'src/shared/global.error'

@Injectable()
export class LanguageService {
  constructor(private languageRepo: LanguageRepo) {}

  // Standard offset-based pagination for admin/management UI
  async findAll(query: LanguagePaginationQueryType): Promise<PaginatedResponseType<LanguageType>> {
    return await this.languageRepo.findAllWithPagination(query)
  }

  async findById(id: string): Promise<LanguageType> {
    const language = await this.languageRepo.findById(id)
    if (!language) {
      throw LanguageError.NotFound
    }
    return language
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
      throw GlobalError.InternalServerError()
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
      throw GlobalError.InternalServerError()
    }
  }

  async delete(id: string, userId: number): Promise<LanguageType> {
    // Check if language exists first
    const existingLanguage = await this.languageRepo.findById(id)
    if (!existingLanguage) {
      throw LanguageError.NotFound
    }

    try {
      const language = await this.languageRepo.delete(id, { deletedById: userId })
      return language
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw LanguageError.NotFound
      }
      // Could be a foreign key constraint violation
      if (error.code === 'P2003') {
        throw LanguageError.CannotDelete
      }
      throw GlobalError.InternalServerError()
    }
  }
}
