import { Injectable } from '@nestjs/common'
import { PermissionRepo } from 'src/routes/permission/permission.repo'
import { CreatePermissionBodyType, UpdatePermissionBodyType } from 'src/routes/permission/permission.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { PermissionAlreadyExistsException } from 'src/routes/permission/permission.error'
import { PaginationService } from 'src/shared/services/pagination.service'
import { PaginationQueryType } from 'src/shared/models/pagination.model'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'

@Injectable()
export class PermissionService {
  constructor(
    private permissionRepo: PermissionRepo,
    private paginationService: PaginationService,
    private i18n: I18nService<I18nTranslations>
  ) {}

  async list(pagination: PaginationQueryType) {
    const result = await this.paginationService.paginate('permission', pagination, {
      where: { deletedAt: null },
      defaultSortField: 'createdAt'
    })

    return {
      ...result,
      message: this.i18n.t('permission.permission.success.GET_SUCCESS')
    }
  }

  async findById(id: number) {
    const permission = await this.permissionRepo.findById(id)
    if (!permission) {
      throw NotFoundRecordException
    }

    return {
      data: permission,
      message: this.i18n.t('permission.permission.success.GET_DETAIL_SUCCESS')
    }
  }

  async create({ data, createdById }: { data: CreatePermissionBodyType; createdById: number }) {
    try {
      const permission = await this.permissionRepo.create({
        createdById,
        data
      })

      return {
        data: permission,
        message: this.i18n.t('permission.permission.success.CREATE_SUCCESS')
      }
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
        data
      })

      return {
        data: permission,
        message: this.i18n.t('permission.permission.success.UPDATE_SUCCESS')
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

  async delete({ id, deletedById }: { id: number; deletedById: number }) {
    try {
      await this.permissionRepo.delete({
        id,
        deletedById
      })
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
}
