import { Injectable } from '@nestjs/common'
import { RoleRepo } from 'src/routes/role/role.repo'
import { CreateRoleBodyType, GetRolesQueryType, UpdateRoleBodyType } from 'src/routes/role/role.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { ProhibitedActionOnBaseRoleException, RoleAlreadyExistsException } from 'src/routes/role/role.error'
import { RoleName } from 'src/shared/constants/role.constant'
import { RedisService } from 'src/shared/services/redis.service'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Injectable()
export class RoleService {
  constructor(
    private roleRepo: RoleRepo,
    private readonly redisService: RedisService,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async list(pagination: GetRolesQueryType) {
    const data = await this.roleRepo.list({
      page: pagination.page,
      limit: pagination.limit,
      name: pagination.name
    })
    return {
      message: this.i18n.t('role.role.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
  }

  async findById(id: string) {
    const role = await this.roleRepo.findById(id)
    if (!role) {
      throw NotFoundRecordException
    }
    return {
      message: this.i18n.t('role.role.success.GET_DETAIL_SUCCESS'),
      data: role
    }
  }

  async create({ data, user }: { data: CreateRoleBodyType; user: AccessTokenPayload }) {
    try {
      const role = await this.roleRepo.create({
        createdById: user.userId,
        data
      })
      return {
        message: this.i18n.t('role.role.success.CREATE_SUCCESS'),
        data: role
      }
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw RoleAlreadyExistsException
      }
      throw error
    }
  }

  /**
   * Kiểm tra xem role có phải là 1 trong 3 role cơ bản không
   */
  private async verifyRole(roleId: string) {
    const role = await this.roleRepo.findById(roleId)
    if (!role) {
      throw NotFoundRecordException
    }
    const baseRoles: string[] = [RoleName.Admin, RoleName.Client, RoleName.Seller]

    if (baseRoles.includes(role.name)) {
      throw ProhibitedActionOnBaseRoleException
    }
  }

  async update({ id, data, user }: { id: string; data: UpdateRoleBodyType; user: AccessTokenPayload }) {
    try {
      await this.verifyRole(id)
      const updatedRole = await this.roleRepo.update({
        id,
        updatedById: user.userId,
        data
      })
      await this.redisService.del(`role:${updatedRole.id}`) // Xóa cache của role đã cập nhật
      return {
        message: this.i18n.t('role.role.success.UPDATE_SUCCESS'),
        data: updatedRole
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      if (isUniqueConstraintPrismaError(error)) {
        throw RoleAlreadyExistsException
      }
      throw error
    }
  }

  async delete({ id, user }: { id: string; user: AccessTokenPayload }) {
    try {
      await this.verifyRole(id)
      await this.roleRepo.delete({
        id,
        deletedById: user.userId
      })
      await this.redisService.del(`role:${id}`) // Xóa cache của role đã xóa
      return {
        message: this.i18n.t('role.role.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
