import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { RoleRepo } from 'src/routes/role/role.repo'
import {
  CreateRoleBodyType,
  GetRolesQueryType,
  UpdateRoleBodyType,
  RoleType,
  AssignPermissionsToRoleBodyType
} from 'src/routes/role/role.model'
import {
  RoleNameAlreadyExistsException,
  RoleNotFoundException,
  RoleDeletedException,
  RoleInUseException,
  CannotDeleteSystemRoleException
} from 'src/routes/role/role.error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { AuditLogService } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { PrismaService } from 'src/shared/services/prisma.service'
import { AuditLog } from 'src/shared/decorators/audit-log.decorator'
import { PaginatedResponseType } from 'src/shared/models/pagination.model'
import { PermissionRepo } from 'src/routes/permission/permission.repo'
import { PermissionNotFoundException } from 'src/routes/permission/permission.error'
import { RoleName, RoleNameValue } from 'src/shared/constants/role.constant'

const SYSTEM_ROLES: readonly RoleNameValue[] = [RoleName.Admin, RoleName.Client] as const

@Injectable()
export class RoleService {
  private readonly logger = new Logger(RoleService.name)

  constructor(
    private readonly roleRepo: RoleRepo,
    private readonly prismaService: PrismaService,
    private readonly auditLogService: AuditLogService,
    private readonly permissionRepo: PermissionRepo
  ) {}

  @AuditLog({
    action: 'ROLE_LIST',
    getDetails: (params, result) => ({
      query: params[0],
      totalItems: result.totalItems,
      itemCount: result.data.length
    })
  })
  async findAll(query?: GetRolesQueryType): Promise<PaginatedResponseType<RoleType>> {
    this.logger.debug(`Finding all roles with query: ${JSON.stringify(query)}`)
    return this.roleRepo.findAll(query)
  }

  @AuditLog({
    action: 'ROLE_GET_BY_ID',
    entity: 'Role',
    getEntityId: (params) => params[0],
    getDetails: (params) => ({
      roleId: params[0],
      includeDeleted: params[1] || false
    })
  })
  async findById(id: number, includeDeleted: boolean = false): Promise<RoleType> {
    this.logger.debug(`Finding role by ID: ${id}, includeDeleted: ${includeDeleted}`)

    const role = await this.roleRepo.findById(id, includeDeleted)

    if (!role) {
      if (includeDeleted) {
        throw RoleNotFoundException(id)
      }
      // Check if it was deleted
      const deletedRole = await this.roleRepo.findById(id, true)
      if (deletedRole) {
        throw RoleDeletedException(id)
      } else {
        throw RoleNotFoundException(id)
      }
    }
    return role
  }

  @AuditLog({
    action: 'ROLE_CREATE',
    entity: 'Role',
    getEntityId: (_, result) => result.id,
    getUserId: (params) => params[0].createdById,
    getDetails: (params, result) => ({
      createdData: params[0].data,
      resultId: result.id
    })
  })
  async create({ data, createdById }: { data: CreateRoleBodyType; createdById: number }): Promise<RoleType> {
    this.logger.debug(`Creating role: ${JSON.stringify(data)}`)
    try {
      return await this.prismaService.$transaction(async (tx) => {
        const existingRoleByName = await this.roleRepo.findByName(data.name, tx)
        if (existingRoleByName) {
          throw RoleNameAlreadyExistsException(data.name)
        }

        if (data.permissionIds && data.permissionIds.length > 0) {
          for (const permissionId of data.permissionIds) {
            const permission = await this.permissionRepo.findById(permissionId, false, tx)
            if (!permission) {
              throw PermissionNotFoundException(permissionId) // Specific error for permission
            }
          }
        }

        return this.roleRepo.create({ createdById, data }, tx)
      })
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      }
      if (isUniqueConstraintPrismaError(error) && error.meta?.target === 'Role_name_key') {
        throw RoleNameAlreadyExistsException(data.name)
      }
      this.logger.error(`Unexpected error during role creation: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
    }
  }

  @AuditLog({
    action: 'ROLE_UPDATE',
    entity: 'Role',
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
    data: UpdateRoleBodyType
    updatedById: number
  }): Promise<RoleType> {
    this.logger.debug(`Updating role ${id}: ${JSON.stringify(data)}`)
    try {
      return await this.prismaService.$transaction(async (tx) => {
        const existingRole = await this.roleRepo.findById(id, false, tx)
        if (!existingRole) {
          const deletedRole = await this.roleRepo.findById(id, true, tx)
          if (deletedRole) {
            throw RoleDeletedException(id)
          } else {
            throw RoleNotFoundException(id)
          }
        }

        if (data.name && data.name !== existingRole.name) {
          const roleWithSameName = await this.roleRepo.findByName(data.name, tx)
          if (roleWithSameName && roleWithSameName.id !== id) {
            throw RoleNameAlreadyExistsException(data.name)
          }
        }

        if (data.permissionIds && data.permissionIds.length > 0) {
          for (const permissionId of data.permissionIds) {
            const permission = await this.permissionRepo.findById(permissionId, false, tx)
            if (!permission) {
              throw PermissionNotFoundException(permissionId)
            }
          }
        }

        return this.roleRepo.update({ id, updatedById, data }, tx)
      })
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      }
      if (isNotFoundPrismaError(error)) {
        throw RoleNotFoundException(id)
      }
      if (isUniqueConstraintPrismaError(error) && data.name && error.meta?.target === 'Role_name_key') {
        throw RoleNameAlreadyExistsException(data.name)
      }
      this.logger.error(`Unexpected error during role update: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
    }
  }

  @AuditLog({
    action: 'ROLE_ASSIGN_PERMISSIONS',
    entity: 'Role',
    getEntityId: (params) => params[0].roleId,
    getUserId: (params) => params[0].updatedById,
    getDetails: (params, result) => ({
      roleId: params[0].roleId,
      permissionIds: params[0].data.permissionIds,
      resultId: result.id
    })
  })
  async assignPermissions({
    roleId,
    data,
    updatedById
  }: {
    roleId: number
    data: AssignPermissionsToRoleBodyType
    updatedById: number
  }): Promise<RoleType> {
    this.logger.debug(`Assigning permissions to role ${roleId}: ${JSON.stringify(data.permissionIds)}`)
    try {
      return await this.prismaService.$transaction(async (tx) => {
        const existingRole = await this.roleRepo.findById(roleId, false, tx)
        if (!existingRole) {
          const deletedRole = await this.roleRepo.findById(roleId, true, tx)
          if (deletedRole) {
            throw RoleDeletedException(roleId)
          } else {
            throw RoleNotFoundException(roleId)
          }
        }

        if (data.permissionIds && data.permissionIds.length > 0) {
          for (const permissionId of data.permissionIds) {
            const permission = await this.permissionRepo.findById(permissionId, false, tx)
            if (!permission) {
              throw PermissionNotFoundException(permissionId)
            }
          }
        }

        return this.roleRepo.assignPermissions({ roleId, updatedById, data }, tx)
      })
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      }
      if (isNotFoundPrismaError(error)) {
        throw RoleNotFoundException(roleId)
      }
      this.logger.error(`Unexpected error during assigning permissions to role: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
    }
  }

  @AuditLog({
    action: 'ROLE_DELETE',
    entity: 'Role',
    getEntityId: (params) => params[0],
    getUserId: (params) => params[1],
    getDetails: (params) => ({
      isHardDelete: params[2] || false,
      roleId: params[0]
    })
  })
  async delete(id: number, deletedById: number, isHardDelete: boolean = false): Promise<{ message: string }> {
    this.logger.debug(`Deleting role ${id} (${isHardDelete ? 'hard' : 'soft'} delete)`)
    try {
      await this.prismaService.$transaction(async (tx) => {
        const existingRole = await this.roleRepo.findById(id, !isHardDelete, tx)
        if (!existingRole) {
          if (!isHardDelete) {
            const alreadyDeletedRole = await this.roleRepo.findById(id, true, tx)
            if (alreadyDeletedRole && alreadyDeletedRole.deletedAt) {
              throw RoleDeletedException(id) // Already soft-deleted
            }
          }
          throw RoleNotFoundException(id) // Not found at all
        }

        if (SYSTEM_ROLES.includes(existingRole.name as RoleNameValue)) {
          throw CannotDeleteSystemRoleException(existingRole.name)
        }

        const userCount = await this.roleRepo.countUsers(id, tx)
        if (userCount > 0) {
          throw RoleInUseException(id)
        }

        if (isHardDelete) {
          await this.roleRepo.hardDelete(id, tx)
        } else {
          if (existingRole.deletedAt) {
            // Already soft-deleted
            throw RoleDeletedException(id)
          }
          await this.roleRepo.softDelete(id, deletedById, tx)
        }
      })
      return {
        message: isHardDelete ? 'Role.HardDelete.Success' : 'Role.SoftDelete.Success'
      }
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      }
      if (isNotFoundPrismaError(error)) {
        throw RoleNotFoundException(id)
      }
      this.logger.error(`Unexpected error during role delete: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
    }
  }

  @AuditLog({
    action: 'ROLE_RESTORE',
    entity: 'Role',
    getEntityId: (params) => params[0],
    getUserId: (params) => params[1],
    getDetails: (params) => ({
      roleId: params[0]
    })
  })
  async restore(id: number, updatedById: number): Promise<RoleType> {
    this.logger.debug(`Restoring role ${id}`)
    try {
      return await this.prismaService.$transaction(async (tx) => {
        const deletedRole = await this.roleRepo.findById(id, true, tx)
        if (!deletedRole) {
          throw RoleNotFoundException(id)
        }
        if (!deletedRole.deletedAt) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'BAD_REQUEST', 'Error.Role.NotDeleted', [
            { code: 'Error.Role.NotDeleted', path: 'roleId', args: { id } }
          ])
        }
        return this.roleRepo.restore(id, updatedById, tx)
      })
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      }
      if (isNotFoundPrismaError(error)) {
        throw RoleNotFoundException(id)
      }
      this.logger.error(`Unexpected error during role restore: ${error.message}`, error.stack)
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'Error.Unexpected')
    }
  }
}
