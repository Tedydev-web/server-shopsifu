import { Injectable } from '@nestjs/common'
import { RoleRepo } from 'src/routes/role/role.repo'
import { CreateRoleBodyType, GetRolesQueryType, UpdateRoleBodyType } from 'src/routes/role/role.model'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/utils/prisma.utils'
import { RoleName } from 'src/shared/constants/role.constant'
import { GlobalError } from 'src/shared/global.error'

@Injectable()
export class RoleService {
  constructor(private roleRepo: RoleRepo) {}

  async list(pagination: GetRolesQueryType) {
    const data = await this.roleRepo.list(pagination)
    return data
  }

  async findById(id: number) {
    const role = await this.roleRepo.findById(id)
    if (!role) {
      throw GlobalError.NotFoundRecordException()
    }
    return role
  }

  async create({ data, createdById }: { data: CreateRoleBodyType; createdById: number }) {
    try {
      const role = await this.roleRepo.create({
        createdById,
        data,
      })
      return role
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw GlobalError.Conflict()
      }
      throw GlobalError.InternalServerError()
    }
  }

  /**
   * Kiểm tra xem role có phải là 1 trong 3 role cơ bản không
   */
  private async verifyRole(roleId: number) {
    const role = await this.roleRepo.findById(roleId)
    if (!role) {
      throw GlobalError.NotFoundRecordException()
    }
    const baseRoles: string[] = [RoleName.Admin, RoleName.Client, RoleName.Seller]

    if (baseRoles.includes(role.name)) {
      throw GlobalError.Forbidden()
    }
  }

  async update({ id, data, updatedById }: { id: number; data: UpdateRoleBodyType; updatedById: number }) {
    try {
      await this.verifyRole(id)
      const updatedRole = await this.roleRepo.update({
        id,
        updatedById,
        data,
      })
      return updatedRole
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw GlobalError.NotFoundRecordException()
      }
      if (isUniqueConstraintPrismaError(error)) {
        throw GlobalError.Conflict()
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: number; deletedById: number }) {
    try {
      await this.verifyRole(id)
      await this.roleRepo.delete({
        id,
        deletedById,
      })
      return {
        message: 'Delete successfully',
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw GlobalError.NotFoundRecordException()
      }
      throw error
    }
  }
}
