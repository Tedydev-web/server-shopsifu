import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { PermissionRepo } from 'src/routes/permission/permission.repo'
import {
  CreatePermissionBodyType,
  GetPermissionsQueryType,
  UpdatePermissionBodyType,
  PermissionType
} from 'src/routes/permission/permission.model'
import {
  PermissionNotFoundException,
  PermissionDeletedException,
  PermissionInUseException,
  PathMethodCombinationExistsException
} from 'src/routes/permission/permission.error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { AuditLogService, AuditLogStatus, AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { PrismaService } from 'src/shared/services/prisma.service'
import { AuditLog } from 'src/shared/decorators/audit-log.decorator'
import { PaginatedResponseType } from 'src/shared/models/pagination.model'

@Injectable()
export class PermissionService {
  private readonly logger = new Logger(PermissionService.name)

  constructor(
    private readonly permissionRepo: PermissionRepo,
    private readonly prismaService: PrismaService,
    private readonly auditLogService: AuditLogService
  ) {}

  @AuditLog({
    action: 'PERMISSION_LIST',
    getDetails: (params, result) => ({
      query: params[0],
      totalItems: result.totalItems,
      itemCount: result.data.length
    })
  })
  async findAll(query?: GetPermissionsQueryType): Promise<PaginatedResponseType<PermissionType>> {
    this.logger.debug(`Finding all permissions with query: ${JSON.stringify(query)}`)

    const { permissions, totalItems } = await this.permissionRepo.findAll(query)

    const page = query?.page || 1
    const limit = query?.all ? 1000 : query?.limit || 10
    const totalPages = Math.ceil(totalItems / limit)

    return {
      data: permissions,
      totalItems,
      page,
      limit,
      totalPages
    }
  }

  @AuditLog({
    action: 'PERMISSION_GET_BY_ID',
    entity: 'Permission',
    getEntityId: (params) => params[0],
    getDetails: (params) => ({
      permissionId: params[0],
      includeDeleted: params[1] || false
    })
  })
  async findById(id: number, includeDeleted: boolean = false): Promise<PermissionType> {
    this.logger.debug(`Finding permission by ID: ${id}, includeDeleted: ${includeDeleted}`)

    const permission = await this.permissionRepo.findById(id, includeDeleted)

    if (!permission) {
      if (includeDeleted) {
        throw PermissionNotFoundException(id)
      }

      const deletedPermission = await this.permissionRepo.findById(id, true)
      if (deletedPermission) {
        throw PermissionDeletedException(id)
      } else {
        throw PermissionNotFoundException(id)
      }
    }

    return permission
  }

  @AuditLog({
    action: 'PERMISSION_CREATE',
    entity: 'Permission',
    getEntityId: (_, result) => result.id,
    getUserId: (params) => params[0].createdById,
    getDetails: (params, result) => ({
      createdData: params[0].data,
      resultId: result.id
    })
  })
  async create({
    data,
    createdById
  }: {
    data: CreatePermissionBodyType
    createdById: number
  }): Promise<PermissionType> {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'PERMISSION_CREATE_ATTEMPT',
      userId: createdById,
      entity: 'Permission',
      status: AuditLogStatus.FAILURE,
      details: { providedData: data }
    }

    try {
      this.logger.debug(`Creating permission: ${JSON.stringify(data)}`)

      const newPermission = await this.prismaService.$transaction(async (tx) => {
        // Kiểm tra xem đã tồn tại permission với path và method giống nhau chưa
        const existingPermission = await this.permissionRepo.findByPathAndMethod(data.path, data.method, true, tx)

        if (existingPermission) {
          if (existingPermission.deletedAt) {
            auditLogEntry.details.reason = 'PERMISSION_DELETED_EXISTS'
            auditLogEntry.entityId = existingPermission.id.toString()
            auditLogEntry.errorMessage = PermissionDeletedException(existingPermission.id).message
            throw PermissionDeletedException(existingPermission.id)
          } else {
            auditLogEntry.details.reason = 'PATH_METHOD_COMBINATION_EXISTS'
            auditLogEntry.errorMessage = PathMethodCombinationExistsException.message
            throw PathMethodCombinationExistsException
          }
        }

        return this.permissionRepo.create(
          {
            createdById,
            data
          },
          tx
        )
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'PERMISSION_CREATE_SUCCESS'
      auditLogEntry.entityId = newPermission.id.toString()
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return newPermission
    } catch (error) {
      auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during permission creation'
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      } else if (isUniqueConstraintPrismaError(error)) {
        auditLogEntry.details.reason = 'PATH_METHOD_COMBINATION_EXISTS'
        auditLogEntry.errorMessage = PathMethodCombinationExistsException.message
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        throw PathMethodCombinationExistsException
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  @AuditLog({
    action: 'PERMISSION_UPDATE',
    entity: 'Permission',
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
    id: number
    data: UpdatePermissionBodyType
    updatedById: number
  }): Promise<PermissionType> {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'PERMISSION_UPDATE_ATTEMPT',
      userId: updatedById,
      entity: 'Permission',
      entityId: id.toString(),
      status: AuditLogStatus.FAILURE,
      details: { updatedData: data }
    }

    try {
      this.logger.debug(`Updating permission ${id}: ${JSON.stringify(data)}`)

      const updatedPermission = await this.prismaService.$transaction(async (tx) => {
        const existingPermission = await this.permissionRepo.findById(id, false, tx)
        if (!existingPermission) {
          const deletedPermission = await this.permissionRepo.findById(id, true, tx)
          if (deletedPermission) {
            auditLogEntry.errorMessage = PermissionDeletedException(id).message
            auditLogEntry.details.reason = 'PERMISSION_ALREADY_DELETED'
            throw PermissionDeletedException(id)
          } else {
            auditLogEntry.errorMessage = PermissionNotFoundException(id).message
            auditLogEntry.details.reason = 'PERMISSION_NOT_FOUND'
            throw PermissionNotFoundException(id)
          }
        }

        // Kiểm tra xem path và method đã tồn tại chưa nếu người dùng cập nhật path hoặc method
        if (data.path || data.method) {
          const path = data.path || existingPermission.path
          const method = data.method || existingPermission.method

          if (path !== existingPermission.path || method !== existingPermission.method) {
            const duplicatePermission = await this.permissionRepo.findByPathAndMethod(path, method, false, tx)

            if (duplicatePermission && duplicatePermission.id !== id) {
              auditLogEntry.details.reason = 'PATH_METHOD_COMBINATION_EXISTS'
              auditLogEntry.errorMessage = PathMethodCombinationExistsException.message
              throw PathMethodCombinationExistsException
            }
          }
        }

        return this.permissionRepo.update(
          {
            id,
            updatedById,
            data
          },
          tx
        )
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'PERMISSION_UPDATE_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return updatedPermission
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during permission update'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        } else if (isNotFoundPrismaError(error)) {
          auditLogEntry.details.reason = 'PERMISSION_NOT_FOUND_PRISMA_ERROR'
          auditLogEntry.errorMessage = PermissionNotFoundException(id).message
        } else if (isUniqueConstraintPrismaError(error)) {
          auditLogEntry.details.reason = 'PATH_METHOD_COMBINATION_EXISTS'
          auditLogEntry.errorMessage = PathMethodCombinationExistsException.message
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  @AuditLog({
    action: 'PERMISSION_DELETE',
    entity: 'Permission',
    getEntityId: (params) => params[0],
    getUserId: (params) => params[1],
    getDetails: (params) => ({
      isHardDelete: params[2] || false,
      permissionId: params[0]
    })
  })
  async delete(id: number, deletedById: number, isHardDelete: boolean = false): Promise<{ message: string }> {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'PERMISSION_DELETE_ATTEMPT',
      userId: deletedById,
      entity: 'Permission',
      entityId: id.toString(),
      status: AuditLogStatus.FAILURE,
      details: { deleteType: isHardDelete ? 'hard' : 'soft' }
    }

    try {
      this.logger.debug(`Deleting permission ${id} (${isHardDelete ? 'hard' : 'soft'} delete)`)

      await this.prismaService.$transaction(async (tx) => {
        const existingPermission = await this.permissionRepo.findById(id, !isHardDelete, tx)
        if (!existingPermission) {
          if (!isHardDelete) {
            const deletedPermission = await this.permissionRepo.findById(id, true, tx)
            if (deletedPermission) {
              auditLogEntry.errorMessage = PermissionDeletedException(id).message
              auditLogEntry.details.reason = 'PERMISSION_ALREADY_DELETED'
              throw PermissionDeletedException(id)
            }
          }
          auditLogEntry.errorMessage = PermissionNotFoundException(id).message
          auditLogEntry.details.reason = 'PERMISSION_NOT_FOUND'
          throw PermissionNotFoundException(id)
        }

        // Kiểm tra xem permission có đang được sử dụng bởi role nào không
        const rolesCount = await this.permissionRepo.countRoles(id, tx)
        if (rolesCount > 0) {
          auditLogEntry.errorMessage = PermissionInUseException(id).message
          auditLogEntry.details.reason = 'PERMISSION_IN_USE'
          auditLogEntry.details.rolesCount = rolesCount
          throw PermissionInUseException(id)
        }

        if (isHardDelete) {
          await this.permissionRepo.hardDelete(id, tx)
        } else {
          await this.permissionRepo.softDelete(id, deletedById, tx)
        }
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = isHardDelete ? 'PERMISSION_HARD_DELETE_SUCCESS' : 'PERMISSION_SOFT_DELETE_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return {
        message: isHardDelete ? 'Permission.HardDelete.Success' : 'Permission.SoftDelete.Success'
      }
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during permission delete'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        } else if (isNotFoundPrismaError(error)) {
          auditLogEntry.details.reason = 'PERMISSION_NOT_FOUND_PRISMA_ERROR'
          auditLogEntry.errorMessage = PermissionNotFoundException(id).message
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  @AuditLog({
    action: 'PERMISSION_RESTORE',
    entity: 'Permission',
    getEntityId: (params) => params[0],
    getUserId: (params) => params[1],
    getDetails: (params) => ({
      permissionId: params[0]
    })
  })
  async restore(id: number, updatedById: number): Promise<PermissionType> {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'PERMISSION_RESTORE_ATTEMPT',
      userId: updatedById,
      entity: 'Permission',
      entityId: id.toString(),
      status: AuditLogStatus.FAILURE,
      details: { permissionId: id }
    }

    try {
      this.logger.debug(`Restoring permission ${id}`)

      const restoredPermission = await this.prismaService.$transaction(async (tx) => {
        const deletedPermission = await this.permissionRepo.findById(id, true, tx)
        if (!deletedPermission) {
          auditLogEntry.errorMessage = PermissionNotFoundException(id).message
          auditLogEntry.details.reason = 'PERMISSION_NOT_FOUND'
          throw PermissionNotFoundException(id)
        }

        if (!deletedPermission.deletedAt) {
          auditLogEntry.errorMessage = 'Permission is not deleted'
          auditLogEntry.details.reason = 'PERMISSION_NOT_DELETED'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'BAD_REQUEST', 'Error.Permission.NotDeleted', [
            { code: 'Error.Permission.NotDeleted', path: 'permissionId', args: { id } }
          ])
        }

        // Kiểm tra xem đã tồn tại permission với path và method giống nhau chưa
        const existingPermission = await this.permissionRepo.findByPathAndMethod(
          deletedPermission.path,
          deletedPermission.method,
          false,
          tx
        )

        if (existingPermission) {
          auditLogEntry.details.reason = 'PATH_METHOD_COMBINATION_EXISTS'
          auditLogEntry.errorMessage = PathMethodCombinationExistsException.message
          throw PathMethodCombinationExistsException
        }

        return this.permissionRepo.restore(id, updatedById, tx)
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'PERMISSION_RESTORE_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return restoredPermission
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during permission restore'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
