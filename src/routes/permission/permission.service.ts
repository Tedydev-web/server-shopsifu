import { Injectable } from '@nestjs/common'
import { PermissionRepo } from 'src/routes/permission/permission.repo'
import {
  CreatePermissionBodyType,
  GetPermissionsQueryType,
  UpdatePermissionBodyType,
  PermissionGroupType,
  PermissionType,
} from 'src/routes/permission/permission.model'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { PermissionAlreadyExistsException } from 'src/routes/permission/permission.error'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { PaginatedResult } from 'src/shared/services/pagination.service'
import { NotFoundRecordException } from 'src/shared/error'

@Injectable()
export class PermissionService {
  constructor(
    private permissionRepo: PermissionRepo,
    private readonly i18n: I18nService<I18nTranslations>,
  ) {}

  async list(pagination: GetPermissionsQueryType): Promise<PaginatedResult<PermissionType>> {
    return await this.permissionRepo.list(pagination)
  }

  async findAllGrouped(): Promise<PermissionGroupType[]> {
    const permissions = await this.permissionRepo.findAll()
    const moduleMap = new Map<string, PermissionType[]>()

    permissions.forEach((permission) => {
      const moduleName = permission.module
      if (!moduleMap.has(moduleName)) {
        moduleMap.set(moduleName, [])
      }
      moduleMap.get(moduleName)!.push(permission)
    })

    const groupedPermissions = Array.from(moduleMap.entries()).map(([module, permissions]) => ({
      module,
      permissions,
    }))

    return groupedPermissions
  }

  async findById(id: number) {
    const permission = await this.permissionRepo.findById(id)
    if (!permission) {
      throw NotFoundRecordException
    }
    return permission
  }

  async create({ data, createdById }: { data: CreatePermissionBodyType; createdById: number }) {
    try {
      return await this.permissionRepo.create({
        createdById,
        data,
      })
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw PermissionAlreadyExistsException
      }
      throw error
    }
  }

  async update({ id, data, updatedById }: { id: number; data: UpdatePermissionBodyType; updatedById: number }) {
    try {
      const permission = await this.permissionRepo.update({
        id,
        updatedById,
        data,
      })
      return permission
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      if (isUniqueConstraintPrismaError(error)) {
        throw PermissionAlreadyExistsException
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: number; deletedById: number }) {
    try {
      await this.permissionRepo.delete({
        id,
        deletedById,
      })
      return {
        message: this.i18n.t('permission.success.DELETE_SUCCESS'),
        // TODO: translate
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
