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
import { AuditLogService, AuditLogStatus, AuditLogData } from 'src/shared/services/audit.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { PrismaService } from 'src/shared/services/prisma.service'
import { AuditLog } from 'src/shared/decorators/audit-log.decorator'

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
  async findAll(query?: GetLanguagesQueryType): Promise<{
    data: LanguageType[]
    totalItems: number
    page?: number
    limit?: number
    totalPages?: number
  }> {
    this.logger.debug(`Finding all languages with query: ${JSON.stringify(query)}`)

    const { languages, totalItems } = await this.languageRepo.findAll(query)

    const page = query?.page || 1
    const limit = query?.limit || 10
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

      // Kiểm tra xem ngôn ngữ có tồn tại nhưng đã bị xóa không
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
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'LANGUAGE_CREATE_ATTEMPT',
      userId: createdById,
      entity: 'Language',
      entityId: data.id,
      status: AuditLogStatus.FAILURE,
      details: { providedData: data }
    }

    try {
      this.logger.debug(`Creating language: ${JSON.stringify(data)}`)

      // Sử dụng transaction để đảm bảo tính toàn vẹn dữ liệu
      const newLanguage = await this.prismaService.$transaction(async (tx) => {
        // Kiểm tra sự tồn tại của ngôn ngữ (bao gồm cả đã xóa)
        const existingLanguage = await this.languageRepo.findById(data.id, true, tx)
        if (existingLanguage) {
          if (existingLanguage.deletedAt) {
            auditLogEntry.details.reason = 'LANGUAGE_DELETED_EXISTS'
            auditLogEntry.errorMessage = LanguageDeletedException(data.id).message
            throw LanguageDeletedException(data.id)
          } else {
            auditLogEntry.details.reason = 'LANGUAGE_ALREADY_EXISTS'
            auditLogEntry.errorMessage = LanguageAlreadyExistsException.message
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

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'LANGUAGE_CREATE_SUCCESS'
      auditLogEntry.entityId = newLanguage.id
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return newLanguage
    } catch (error) {
      auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during language creation'
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      } else if (isUniqueConstraintPrismaError(error)) {
        auditLogEntry.details.reason = 'LANGUAGE_ID_ALREADY_EXISTS'
        auditLogEntry.errorMessage = LanguageAlreadyExistsException.message
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        throw LanguageAlreadyExistsException
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
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
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'LANGUAGE_UPDATE_ATTEMPT',
      userId: updatedById,
      entity: 'Language',
      entityId: id,
      status: AuditLogStatus.FAILURE,
      details: { updatedData: data }
    }

    try {
      this.logger.debug(`Updating language ${id}: ${JSON.stringify(data)}`)

      // Sử dụng transaction
      const updatedLanguage = await this.prismaService.$transaction(async (tx) => {
        // Kiểm tra sự tồn tại của ngôn ngữ
        const existingLanguage = await this.languageRepo.findById(id, false, tx)
        if (!existingLanguage) {
          // Kiểm tra xem đã bị xóa chưa
          const deletedLanguage = await this.languageRepo.findById(id, true, tx)
          if (deletedLanguage) {
            auditLogEntry.errorMessage = LanguageDeletedException(id).message
            auditLogEntry.details.reason = 'LANGUAGE_ALREADY_DELETED'
            throw LanguageDeletedException(id)
          } else {
            auditLogEntry.errorMessage = LanguageNotFoundException(id).message
            auditLogEntry.details.reason = 'LANGUAGE_NOT_FOUND'
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

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'LANGUAGE_UPDATE_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return updatedLanguage
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during language update'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        } else if (isNotFoundPrismaError(error)) {
          auditLogEntry.details.reason = 'LANGUAGE_NOT_FOUND_PRISMA_ERROR'
          auditLogEntry.errorMessage = LanguageNotFoundException(id).message
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
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
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'LANGUAGE_DELETE_ATTEMPT',
      userId: deletedById,
      entity: 'Language',
      entityId: id,
      status: AuditLogStatus.FAILURE,
      details: { deleteType: isHardDelete ? 'hard' : 'soft' }
    }

    try {
      this.logger.debug(`Deleting language ${id} (${isHardDelete ? 'hard' : 'soft'} delete)`)

      await this.prismaService.$transaction(async (tx) => {
        // Kiểm tra sự tồn tại của ngôn ngữ
        const existingLanguage = await this.languageRepo.findById(id, !isHardDelete, tx)
        if (!existingLanguage) {
          if (!isHardDelete) {
            // Kiểm tra xem đã bị xóa chưa (chỉ khi là soft delete)
            const deletedLanguage = await this.languageRepo.findById(id, true, tx)
            if (deletedLanguage) {
              auditLogEntry.errorMessage = LanguageDeletedException(id).message
              auditLogEntry.details.reason = 'LANGUAGE_ALREADY_DELETED'
              throw LanguageDeletedException(id)
            }
          }
          auditLogEntry.errorMessage = LanguageNotFoundException(id).message
          auditLogEntry.details.reason = 'LANGUAGE_NOT_FOUND'
          throw LanguageNotFoundException(id)
        }

        // Kiểm tra xem ngôn ngữ có đang được sử dụng không
        const referenceCount = await this.languageRepo.countReferences(id, tx)
        if (referenceCount > 0) {
          auditLogEntry.errorMessage = LanguageInUseException(id).message
          auditLogEntry.details.reason = 'LANGUAGE_IN_USE'
          auditLogEntry.details.referenceCount = referenceCount
          throw LanguageInUseException(id)
        }

        // Thực hiện xóa
        if (isHardDelete) {
          await this.languageRepo.hardDelete(id, tx)
        } else {
          await this.languageRepo.softDelete(id, deletedById, tx)
        }
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = isHardDelete ? 'LANGUAGE_HARD_DELETE_SUCCESS' : 'LANGUAGE_SOFT_DELETE_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return {
        message: isHardDelete ? 'Language.HardDelete.Success' : 'Language.SoftDelete.Success'
      }
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during language delete'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        } else if (isNotFoundPrismaError(error)) {
          auditLogEntry.details.reason = 'LANGUAGE_NOT_FOUND_PRISMA_ERROR'
          auditLogEntry.errorMessage = LanguageNotFoundException(id).message
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
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
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'LANGUAGE_RESTORE_ATTEMPT',
      userId: updatedById,
      entity: 'Language',
      entityId: id,
      status: AuditLogStatus.FAILURE,
      details: { languageId: id }
    }

    try {
      this.logger.debug(`Restoring language ${id}`)

      const restoredLanguage = await this.prismaService.$transaction(async (tx) => {
        // Kiểm tra xem ngôn ngữ có tồn tại nhưng đã bị xóa không
        const deletedLanguage = await this.languageRepo.findById(id, true, tx)
        if (!deletedLanguage) {
          auditLogEntry.errorMessage = LanguageNotFoundException(id).message
          auditLogEntry.details.reason = 'LANGUAGE_NOT_FOUND'
          throw LanguageNotFoundException(id)
        }

        if (!deletedLanguage.deletedAt) {
          auditLogEntry.errorMessage = 'Language is not deleted'
          auditLogEntry.details.reason = 'LANGUAGE_NOT_DELETED'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'BAD_REQUEST', 'Error.Language.NotDeleted', [
            { code: 'Error.Language.NotDeleted', path: 'languageId', args: { id } }
          ])
        }

        return this.languageRepo.restore(id, updatedById, tx)
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'LANGUAGE_RESTORE_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return restoredLanguage
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during language restore'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
