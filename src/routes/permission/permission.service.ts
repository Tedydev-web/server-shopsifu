  import { Injectable } from '@nestjs/common'
import { PermissionRepo } from 'src/routes/permission/permission.repo'
import {
  CreatePermissionBodyType,
  UpdatePermissionBodyType,
  PermissionPaginationQueryType,
  PermissionType,
  PaginatedResponseType,
} from 'src/routes/permission/permission.model'
import { PermissionError } from 'src/routes/permission/permission.error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/utils/prisma.utils'

@Injectable()
export class PermissionService {
  constructor(private permissionRepo: PermissionRepo) {}

  async list(pagination: PermissionPaginationQueryType): Promise<PaginatedResponseType<PermissionType>> {
    const data = await this.permissionRepo.findAllWithPagination(pagination)
    return data
  }

  async findById(id: number): Promise<PermissionType> {
    const permission = await this.permissionRepo.findById(id)
    if (!permission) {
      throw PermissionError.NotFound
    }
    return permission
  }

  async create({
    data,
    createdById,
  }: {
    data: CreatePermissionBodyType
    createdById: number
  }): Promise<PermissionType> {
    try {
      return await this.permissionRepo.create({
        createdById,
        data,
      })
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw PermissionError.AlreadyExists
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
    data: UpdatePermissionBodyType
    updatedById: number
  }): Promise<PermissionType> {
    try {
      const permission = await this.permissionRepo.updatePermission(id, updatedById, data)
      return permission
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw PermissionError.NotFound
      }
      if (isUniqueConstraintPrismaError(error)) {
        throw PermissionError.AlreadyExists
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: number; deletedById: number }): Promise<{ message: string }> {
    try {
      await this.permissionRepo.softDeletePermission(id, deletedById)
      return {
        message: 'permission.success.DELETE_SUCCESS',
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw PermissionError.NotFound
      }
      throw error
    }
  }
}
