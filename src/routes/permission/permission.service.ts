import { Inject, Injectable } from '@nestjs/common'
import { PermissionRepo } from 'src/routes/permission/permission.repo'
import {
  CreatePermissionBodyType,
  GetPermissionsQueryType,
  UpdatePermissionBodyType
} from 'src/routes/permission/permission.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { PermissionAlreadyExistsException } from 'src/routes/permission/permission.error'
import { CACHE_MANAGER } from '@nestjs/cache-manager'
import { Cache } from 'cache-manager'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class PermissionService {
  constructor(
    private permissionRepo: PermissionRepo,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async list(pagination: GetPermissionsQueryType) {
    const data = await this.permissionRepo.list(pagination)
    return {
      message: this.i18n.t('permission.permission.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
  }

  async findById(id: string) {
    const permission = await this.permissionRepo.findById(id)
    if (!permission) {
      throw NotFoundRecordException
    }
    return {
      message: this.i18n.t('permission.permission.success.GET_DETAIL_SUCCESS'),
      data: permission
    }
  }

  async create({ data, createdById }: { data: CreatePermissionBodyType; createdById: string }) {
    try {
      const permission = await this.permissionRepo.create({
        createdById,
        data
      })
      return {
        message: this.i18n.t('permission.permission.success.CREATE_SUCCESS'),
        data: permission
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw PermissionAlreadyExistsException
      }
      throw error
    }
  }

  async update({ id, data, updatedById }: { id: string; data: UpdatePermissionBodyType; updatedById: string }) {
    try {
      const permission = await this.permissionRepo.update({
        id,
        updatedById,
        data
      })
      const { roles } = permission
      await this.deleteCachedRole(roles)
      return {
        message: this.i18n.t('permission.permission.success.UPDATE_SUCCESS'),
        data: permission
      }
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

  async delete({ id, deletedById }: { id: string; deletedById: string }) {
    try {
      const permission = await this.permissionRepo.delete({
        id,
        deletedById
      })
      const { roles } = permission
      await this.deleteCachedRole(roles)
      return {
        message: this.i18n.t('permission.permission.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  deleteCachedRole(roles: { id: string }[]) {
    return Promise.all(
      roles.map((role) => {
        const cacheKey = `role:${role.id}`
        return this.cacheManager.del(cacheKey)
      })
    )
  }
}
