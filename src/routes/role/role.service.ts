import { Injectable } from '@nestjs/common'
import { RoleRepo } from 'src/routes/role/role.repo'
import {
  CreateRoleBodyType,
  UpdateRoleBodyType,
  RoleType,
  PaginatedResponseType,
  RolePaginationQueryType,
} from 'src/routes/role/role.model'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/utils/prisma.utils'
import { RoleError } from 'src/routes/role/role.error'
import { RoleName } from 'src/shared/constants/role.constant'

@Injectable()
export class RoleService {
  constructor(private roleRepo: RoleRepo) {}

  private async verifyRole(roleId: number) {
    const role = await this.roleRepo.findById(roleId)
    if (!role) {
      throw RoleError.NOT_FOUND
    }
    const baseRoles: string[] = [RoleName.Admin, RoleName.Client, RoleName.Seller]

    if (baseRoles.includes(role.name)) {
      throw RoleError.CANNOT_UPDATE_DEFAULT_ROLE
    }
  }

  async list(pagination: RolePaginationQueryType): Promise<PaginatedResponseType<RoleType>> {
    const data = await this.roleRepo.findAllWithPagination(pagination)
    return data
  }

  async findById(id: number): Promise<RoleType> {
    const role = await this.roleRepo.findById(id)
    if (!role) {
      throw RoleError.NOT_FOUND
    }
    return role
  }

  async create({ data, createdById }: { data: CreateRoleBodyType; createdById: number }): Promise<RoleType> {
    const existingRole = await this.roleRepo.findByName(data.name)
    if (existingRole) {
      throw RoleError.ALREADY_EXISTS
    }

    try {
      const role = await this.roleRepo.create({
        createdById,
        data,
      })
      return role
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw RoleError.ALREADY_EXISTS
      }
      throw error
    }
  }

  async update({
    id,
    data,
    updatedById,
  }: {
    id: number
    data: UpdateRoleBodyType
    updatedById: number
  }): Promise<RoleType> {
    await this.verifyRole(id)

    const existingRole = await this.roleRepo.findByNameExcludingId(data.name, id)
    if (existingRole) {
      throw RoleError.ALREADY_EXISTS
    }

    try {
      const role = await this.roleRepo.updateRoleWithPermissions(id, updatedById, data)
      return role
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw RoleError.NOT_FOUND
      }
      if (isUniqueConstraintPrismaError(error)) {
        throw RoleError.ALREADY_EXISTS
      }
      if (error instanceof Error && error.message.includes('Permission with id has been deleted')) {
        throw RoleError.DELETED_PERMISSION_INCLUDED
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: number; deletedById: number }): Promise<{ message: string }> {
    try {
      await this.verifyRole(id)
      await this.roleRepo.softDeleteRole(id, deletedById)
      return {
        message: 'role.success.DELETE_SUCCESS',
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw RoleError.NOT_FOUND
      }
      throw error
    }
  }
}
