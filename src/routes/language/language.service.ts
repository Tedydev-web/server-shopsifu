import { Injectable } from '@nestjs/common'
import { LanguageRepo } from 'src/routes/language/language.repo'
import { CreateLanguageBodyType, UpdateLanguageBodyType, LanguageType } from 'src/routes/language/language.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { LanguageAlreadyExistsException } from 'src/routes/language/language.error'
import { AuditLogService, AuditLogStatus, AuditLogData } from 'src/shared/services/audit.service'
import { ApiException } from 'src/shared/exceptions/api.exception'

@Injectable()
export class LanguageService {
  constructor(
    private languageRepo: LanguageRepo,
    private readonly auditLogService: AuditLogService
  ) {}

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
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'LANGUAGE_CREATE_ATTEMPT',
      userId: createdById,
      entity: 'Language',
      entityId: data.id,
      status: AuditLogStatus.FAILURE,
      details: { providedData: data }
    }

    try {
      const newLanguage = await this.languageRepo.create({
        createdById,
        data
      })
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'LANGUAGE_CREATE_SUCCESS'
      this.auditLogService.record(auditLogEntry as AuditLogData)
      return newLanguage
    } catch (error) {
      auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during language creation'
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      if (isUniqueConstraintPrismaError(error)) {
        auditLogEntry.details.reason = 'LANGUAGE_ID_ALREADY_EXISTS'
        auditLogEntry.errorMessage = LanguageAlreadyExistsException.message
        this.auditLogService.record(auditLogEntry as AuditLogData)
        throw LanguageAlreadyExistsException
      }
      this.auditLogService.record(auditLogEntry as AuditLogData)
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
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'LANGUAGE_UPDATE_ATTEMPT',
      userId: updatedById,
      entity: 'Language',
      entityId: id,
      status: AuditLogStatus.FAILURE,
      details: { updatedData: data }
    }
    try {
      const existingLanguage = await this.languageRepo.findById(id)
      if (!existingLanguage) {
        auditLogEntry.errorMessage = NotFoundRecordException('Error.Language.NotFoundOnUpdate', 'RESOURCE_NOT_FOUND', [
          { code: 'Error.Language.NotFoundOnUpdate', args: { id } }
        ]).message
        auditLogEntry.details.reason = 'LANGUAGE_NOT_FOUND_PRE_UPDATE_CHECK'
        this.auditLogService.record(auditLogEntry as AuditLogData)
        throw NotFoundRecordException('Error.Language.NotFoundOnUpdate', 'RESOURCE_NOT_FOUND', [
          { code: 'Error.Language.NotFoundOnUpdate', args: { id } }
        ])
      }

      const updatedLanguage = await this.languageRepo.update({
        id,
        updatedById,
        data
      })
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'LANGUAGE_UPDATE_SUCCESS'
      this.auditLogService.record(auditLogEntry as AuditLogData)
      return updatedLanguage
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during language update'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      if (isNotFoundPrismaError(error) && auditLogEntry.details.reason !== 'LANGUAGE_NOT_FOUND_PRE_UPDATE_CHECK') {
        auditLogEntry.details.reason = 'LANGUAGE_NOT_FOUND_ON_UPDATE_REPO_CALL'
        auditLogEntry.errorMessage = NotFoundRecordException('Error.Language.NotFoundOnUpdate', 'RESOURCE_NOT_FOUND', [
          { code: 'Error.Language.NotFoundOnUpdate', args: { id } }
        ]).message
      }
      this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async delete(id: string, deletedById: number): Promise<{ message: string }> {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'LANGUAGE_DELETE_ATTEMPT',
      userId: deletedById,
      entity: 'Language',
      entityId: id,
      status: AuditLogStatus.FAILURE,
      details: { deleteType: 'hard' }
    }
    try {
      const existingLanguage = await this.languageRepo.findById(id)
      if (!existingLanguage) {
        auditLogEntry.errorMessage = NotFoundRecordException('Error.Language.NotFoundOnDelete', 'RESOURCE_NOT_FOUND', [
          { code: 'Error.Language.NotFoundOnDelete', args: { id } }
        ]).message
        auditLogEntry.details.reason = 'LANGUAGE_NOT_FOUND_PRE_DELETE_CHECK'
        this.auditLogService.record(auditLogEntry as AuditLogData)
        throw NotFoundRecordException('Error.Language.NotFoundOnDelete', 'RESOURCE_NOT_FOUND', [
          { code: 'Error.Language.NotFoundOnDelete', args: { id } }
        ])
      }
      await this.languageRepo.delete(id, true)
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'LANGUAGE_DELETE_SUCCESS'
      this.auditLogService.record(auditLogEntry as AuditLogData)
      return {
        message: 'Language.Delete.Success'
      }
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during language delete'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      if (isNotFoundPrismaError(error) && auditLogEntry.details.reason !== 'LANGUAGE_NOT_FOUND_PRE_DELETE_CHECK') {
        auditLogEntry.details.reason = 'LANGUAGE_NOT_FOUND_ON_DELETE_REPO_CALL'
        auditLogEntry.errorMessage = NotFoundRecordException('Error.Language.NotFoundOnDelete', 'RESOURCE_NOT_FOUND', [
          { code: 'Error.Language.NotFoundOnDelete', args: { id } }
        ]).message
      }
      this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
