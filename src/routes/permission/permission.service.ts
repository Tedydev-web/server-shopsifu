import { Injectable } from '@nestjs/common'
import { PermissionRepo } from 'src/routes/permission/permission.repo'
import {
  CreatePermissionBodyType,
  GetPermissionsQueryType,
  UpdatePermissionBodyType
} from 'src/routes/permission/permission.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { PermissionAlreadyExistsException } from 'src/routes/permission/permission.error'
import { RedisService } from 'src/shared/services/redis.service'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Injectable()
export class PermissionService {
  constructor(
    private permissionRepo: PermissionRepo,
    private readonly redisService: RedisService,
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

  async create({ data, user }: { data: CreatePermissionBodyType; user: AccessTokenPayload }) {
    try {
      const permission = await this.permissionRepo.create({
        createdById: user.userId,
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

  async update({ id, data, user }: { id: string; data: UpdatePermissionBodyType; user: AccessTokenPayload }) {
    try {
      const permission = await this.permissionRepo.update({
        id,
        updatedById: user.userId,
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

  async delete({ id, user }: { id: string; user: AccessTokenPayload }) {
    try {
      const permission = await this.permissionRepo.delete({
        id,
        deletedById: user.userId
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
        return this.redisService.del(cacheKey)
      })
    )
  }
}
