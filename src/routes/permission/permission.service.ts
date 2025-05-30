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
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/utils/type-guards.utils'
import { AuditLogService } from 'src/routes/audit-log/audit-log.service'
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
    this.logger.debug(`Creating permission: ${JSON.stringify(data)}`)
    try {
      const newPermission = await this.prismaService.$transaction(async (tx) => {
        const existingPermission = await this.permissionRepo.findByPathAndMethod(data.path, data.method, true, tx)

        if (existingPermission) {
          if (existingPermission.deletedAt) {
            throw PermissionDeletedException(existingPermission.id)
          } else {
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
      return newPermission
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      } else if (isUniqueConstraintPrismaError(error)) {
        throw PathMethodCombinationExistsException
      }
      this.logger.error(`Unexpected error during permission creation: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
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
    this.logger.debug(`Updating permission ${id}: ${JSON.stringify(data)}`)
    try {
      const updatedPermission = await this.prismaService.$transaction(async (tx) => {
        const existingPermission = await this.permissionRepo.findById(id, false, tx)
        if (!existingPermission) {
          const deletedPermission = await this.permissionRepo.findById(id, true, tx)
          if (deletedPermission) {
            throw PermissionDeletedException(id)
          } else {
            throw PermissionNotFoundException(id)
          }
        }

        if (data.path || data.method) {
          const path = data.path || existingPermission.path
          const method = data.method || existingPermission.method

          if (path !== existingPermission.path || method !== existingPermission.method) {
            const duplicatePermission = await this.permissionRepo.findByPathAndMethod(path, method, false, tx)

            if (duplicatePermission && duplicatePermission.id !== id) {
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
      return updatedPermission
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      } else if (isNotFoundPrismaError(error)) {
        throw PermissionNotFoundException(id)
      } else if (isUniqueConstraintPrismaError(error)) {
        throw PathMethodCombinationExistsException
      }
      this.logger.error(`Unexpected error during permission update: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
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
    this.logger.debug(`Deleting permission ${id} (${isHardDelete ? 'hard' : 'soft'} delete)`)
    try {
      await this.prismaService.$transaction(async (tx) => {
        const existingPermission = await this.permissionRepo.findById(id, !isHardDelete, tx)
        if (!existingPermission) {
          if (!isHardDelete) {
            const deletedPermission = await this.permissionRepo.findById(id, true, tx)
            if (deletedPermission) {
              throw PermissionDeletedException(id)
            }
          }
          throw PermissionNotFoundException(id)
        }

        const roleCount = await this.permissionRepo.countRoles(id, tx)
        if (roleCount > 0) {
          throw PermissionInUseException(id)
        }

        if (isHardDelete) {
          await this.permissionRepo.hardDelete(id, tx)
        } else {
          await this.permissionRepo.softDelete(id, deletedById, tx)
        }
      })

      return {
        message: isHardDelete ? 'Permission.HardDelete.Success' : 'Permission.SoftDelete.Success'
      }
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      } else if (isNotFoundPrismaError(error)) {
        throw PermissionNotFoundException(id)
      }
      this.logger.error(`Unexpected error during permission delete: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
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
    this.logger.debug(`Restoring permission ${id}`)
    try {
      const restoredPermission = await this.prismaService.$transaction(async (tx) => {
        const deletedPermission = await this.permissionRepo.findById(id, true, tx)
        if (!deletedPermission) {
          throw PermissionNotFoundException(id)
        }

        if (!deletedPermission.deletedAt) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'BAD_REQUEST', 'Error.Permission.NotDeleted', [
            { code: 'Error.Permission.NotDeleted', path: 'permissionId', args: { id } }
          ])
        }

        return this.permissionRepo.restore(id, updatedById, tx)
      })
      return restoredPermission
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      } else if (isNotFoundPrismaError(error)) {
        throw PermissionNotFoundException(id)
      }
      this.logger.error(`Unexpected error during permission restore: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
    }
  }
}
