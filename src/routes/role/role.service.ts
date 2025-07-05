import { BadRequestException, Injectable } from '@nestjs/common'
import { RoleRepo } from 'src/routes/role/role.repo'
import { CreateRoleBodyType, UpdateRoleBodyType } from 'src/routes/role/role.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { ProhibitedActionOnBaseRoleException, RoleAlreadyExistsException } from 'src/routes/role/role.error'
import { RoleName } from 'src/shared/constants/role.constant'
import { PaginationService } from 'src/shared/services/pagination.service'
import { PaginationQueryType } from 'src/shared/models/pagination.model'
import { OrderBy, SortBy } from 'src/shared/constants/other.constant'

@Injectable()
export class RoleService {
  constructor(
    private roleRepo: RoleRepo,
    private paginationService: PaginationService,
  ) {}

  async list(props: { pagination: PaginationQueryType; filters: any }) {
    // Xây dựng where clause từ filters
    const where = this.buildWhereClause(props.filters)

    // Xây dựng orderBy từ pagination và filters
    const orderBy = this.buildOrderBy(props.pagination, props.filters)

    return this.paginationService.paginate('role', props.pagination, {
      where,
      orderBy,
      defaultSortField: 'createdAt',
    })
  }

  private buildWhereClause(filters: any) {
    const where: any = { deletedAt: null }

    // Hỗ trợ search theo tên và description
    if (filters.search) {
      const searchTerm = filters.search
      where.OR = [
        {
          name: {
            contains: searchTerm,
            mode: 'insensitive',
          },
        },
        {
          description: {
            contains: searchTerm,
            mode: 'insensitive',
          },
        },
      ]
    }

    // Filter theo tên
    if (filters.name) {
      where.name = {
        contains: filters.name,
        mode: 'insensitive',
      }
    }

    // Filter theo description
    if (filters.description) {
      where.description = {
        contains: filters.description,
        mode: 'insensitive',
      }
    }

    // Filter theo trạng thái active
    if (filters.isActive !== undefined) {
      where.isActive = filters.isActive === 'true'
    }

    return where
  }

  private buildOrderBy(pagination: PaginationQueryType, filters: any) {
    const { sortBy = SortBy.CreatedAt, sortOrder = OrderBy.Desc } = filters

    if (sortBy === SortBy.Name) {
      return [{ name: sortOrder }]
    }

    return [{ createdAt: sortOrder }]
  }

  async findById(id: number) {
    const role = await this.roleRepo.findById(id)
    if (!role) {
      throw NotFoundRecordException
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
        throw RoleAlreadyExistsException
      }
      throw error
    }
  }

  /**
   * Kiểm tra xem role có phải là 1 trong 3 role cơ bản không
   */
  private async verifyRole(roleId: number) {
    const role = await this.roleRepo.findById(roleId)
    if (!role) {
      throw NotFoundRecordException
    }
    const baseRoles: string[] = [RoleName.Admin, RoleName.Client, RoleName.Seller]

    if (baseRoles.includes(role.name)) {
      throw ProhibitedActionOnBaseRoleException
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
        throw NotFoundRecordException
      }
      if (isUniqueConstraintPrismaError(error)) {
        throw RoleAlreadyExistsException
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
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
