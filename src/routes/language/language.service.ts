import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { LanguageRepo } from 'src/routes/language/language.repo'
import {
  CreateLanguageBodyType,
  GetLanguagesQueryType,
  UpdateLanguageBodyType,
  LanguageType
} from 'src/routes/language/language.model'
import {
  LanguageAlreadyExistsException,
  LanguageNotFoundException,
  LanguageDeletedException,
  LanguageInUseException
} from 'src/routes/language/language.error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { AuditLogService, AuditLogStatus, AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { PrismaService } from 'src/shared/services/prisma.service'
import { AuditLog } from 'src/shared/decorators/audit-log.decorator'
import { PaginatedResponseType } from 'src/shared/models/pagination.model'

@Injectable()
export class LanguageService {
  private readonly logger = new Logger(LanguageService.name)

  constructor(
    private readonly languageRepo: LanguageRepo,
    private readonly prismaService: PrismaService,
    private readonly auditLogService: AuditLogService
  ) {}

  @AuditLog({
    action: 'LANGUAGE_LIST',
    getDetails: (params, result) => ({
      query: params[0],
      totalItems: result.totalItems,
      itemCount: result.data.length
    })
  })
  async findAll(query?: GetLanguagesQueryType): Promise<PaginatedResponseType<LanguageType>> {
    this.logger.debug(`Finding all languages with query: ${JSON.stringify(query)}`)

    const { languages, totalItems } = await this.languageRepo.findAll(query)

    const page = query?.page || 1
    const limit = query?.all ? 1000 : query?.limit || 10
    const totalPages = Math.ceil(totalItems / limit)

    return {
      data: languages,
      totalItems,
      page,
      limit,
      totalPages
    }
  }

  @AuditLog({
    action: 'LANGUAGE_GET_BY_ID',
    entity: 'Language',
    getEntityId: (params) => params[0],
    getDetails: (params) => ({
      languageId: params[0],
      includeDeleted: params[1] || false
    })
  })
  async findById(id: string, includeDeleted: boolean = false): Promise<LanguageType> {
    this.logger.debug(`Finding language by ID: ${id}, includeDeleted: ${includeDeleted}`)

    const language = await this.languageRepo.findById(id, includeDeleted)

    if (!language) {
      if (includeDeleted) {
        throw LanguageNotFoundException(id)
      }

      const deletedLanguage = await this.languageRepo.findById(id, true)
      if (deletedLanguage) {
        throw LanguageDeletedException(id)
      } else {
        throw LanguageNotFoundException(id)
      }
    }

    return language
  }

  @AuditLog({
    action: 'LANGUAGE_CREATE',
    entity: 'Language',
    getEntityId: (params, result) => result.id,
    getUserId: (params) => params[0].createdById,
    getDetails: (params, result) => ({
      createdData: params[0].data,
      resultId: result.id
    })
  })
  async create({ data, createdById }: { data: CreateLanguageBodyType; createdById: number }): Promise<LanguageType> {
    this.logger.debug(`Creating language: ${JSON.stringify(data)}`)

    try {
      const newLanguage = await this.prismaService.$transaction(async (tx) => {
        const existingLanguage = await this.languageRepo.findById(data.id, true, tx)
        if (existingLanguage) {
          if (existingLanguage.deletedAt) {
            throw LanguageDeletedException(data.id)
          } else {
            throw LanguageAlreadyExistsException
          }
        }

        return this.languageRepo.create(
          {
            createdById,
            data
          },
          tx
        )
      })
      return newLanguage
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      } else if (isUniqueConstraintPrismaError(error)) {
        throw LanguageAlreadyExistsException
      }
      this.logger.error(`Unexpected error during language creation: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
    }
  }

  @AuditLog({
    action: 'LANGUAGE_UPDATE',
    entity: 'Language',
    getEntityId: (params) => params[0].id,
    getUserId: (params) => params[0].updatedById,
    getDetails: (params, result) => ({
      updatedData: params[0].data,
      resultId: result.id
    })
  })
  async update({
    id,
    data,
    updatedById
  }: {
    id: string
    data: UpdateLanguageBodyType
    updatedById: number
  }): Promise<LanguageType> {
    this.logger.debug(`Updating language ${id}: ${JSON.stringify(data)}`)
    try {
      const updatedLanguage = await this.prismaService.$transaction(async (tx) => {
        const existingLanguage = await this.languageRepo.findById(id, false, tx)
        if (!existingLanguage) {
          const deletedLanguage = await this.languageRepo.findById(id, true, tx)
          if (deletedLanguage) {
            throw LanguageDeletedException(id)
          } else {
            throw LanguageNotFoundException(id)
          }
        }

        return this.languageRepo.update(
          {
            id,
            updatedById,
            data
          },
          tx
        )
      })
      return updatedLanguage
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      } else if (isNotFoundPrismaError(error)) {
        throw LanguageNotFoundException(id)
      }
      this.logger.error(`Unexpected error during language update: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
    }
  }

  @AuditLog({
    action: 'LANGUAGE_DELETE',
    entity: 'Language',
    getEntityId: (params) => params[0],
    getUserId: (params) => params[1],
    getDetails: (params) => ({
      isHardDelete: params[2] || false,
      languageId: params[0]
    })
  })
  async delete(id: string, deletedById: number, isHardDelete: boolean = false): Promise<{ message: string }> {
    this.logger.debug(`Deleting language ${id} (${isHardDelete ? 'hard' : 'soft'} delete)`)

    try {
      await this.prismaService.$transaction(async (tx) => {
        const existingLanguage = await this.languageRepo.findById(id, !isHardDelete, tx)
        if (!existingLanguage) {
          if (!isHardDelete) {
            const deletedLanguage = await this.languageRepo.findById(id, true, tx)
            if (deletedLanguage) {
              throw LanguageDeletedException(id)
            }
          }
          throw LanguageNotFoundException(id)
        }

        const referenceCount = await this.languageRepo.countReferences(id, tx)
        if (referenceCount > 0) {
          throw LanguageInUseException(id)
        }

        if (isHardDelete) {
          await this.languageRepo.hardDelete(id, tx)
        } else {
          await this.languageRepo.softDelete(id, deletedById, tx)
        }
      })

      return {
        message: isHardDelete ? 'Language.HardDelete.Success' : 'Language.SoftDelete.Success'
      }
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      } else if (isNotFoundPrismaError(error)) {
        throw LanguageNotFoundException(id)
      }
      this.logger.error(`Unexpected error during language delete: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
    }
  }

  @AuditLog({
    action: 'LANGUAGE_RESTORE',
    entity: 'Language',
    getEntityId: (params) => params[0],
    getUserId: (params) => params[1],
    getDetails: (params) => ({
      languageId: params[0]
    })
  })
  async restore(id: string, updatedById: number): Promise<LanguageType> {
    this.logger.debug(`Restoring language ${id}`)

    try {
      const restoredLanguage = await this.prismaService.$transaction(async (tx) => {
        const deletedLanguage = await this.languageRepo.findById(id, true, tx)
        if (!deletedLanguage) {
          throw LanguageNotFoundException(id)
        }

        if (!deletedLanguage.deletedAt) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'BAD_REQUEST', 'Error.Language.NotDeleted', [
            { code: 'Error.Language.NotDeleted', path: 'languageId', args: { id } }
          ])
        }

        return this.languageRepo.restore(id, updatedById, tx)
      })

      return restoredLanguage
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      } else if (isNotFoundPrismaError(error)) {
        throw LanguageNotFoundException(id)
      }
      this.logger.error(`Unexpected error during language restore: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
    }
  }
}
