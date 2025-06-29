import { HttpStatus, Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import {
  CreateRoleBodyType,
  RoleWithPermissionsType,
  UpdateRoleBodyType,
  RoleType,
  PaginatedResponseType,
  RolePaginationQueryType,
} from 'src/routes/role/role.model'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { ApiException } from 'src/shared/exceptions/api.exception'

@Injectable()
export class RoleRepo extends BaseRepository<RoleType> {
  constructor(prismaService: PrismaService) {
    super(prismaService, 'role')
  }

  protected getSearchableFields(): string[] {
    return ['name', 'description']
  }

  protected getSortableFields(): string[] {
    return ['id', 'name', 'description', 'isActive', 'createdAt', 'updatedAt']
  }

  async findAllWithPagination(query: RolePaginationQueryType): Promise<PaginatedResponseType<RoleType>> {
    return this.paginate(query, { deletedAt: null })
  }

  async findByName(name: string, prismaClient?: PrismaTransactionClient): Promise<RoleType | null> {
    const client = this.getClient(prismaClient)
    return client.role.findFirst({
      where: {
        name: {
          equals: name,
          mode: 'insensitive',
        },
        deletedAt: null,
      },
    })
  }

  async findByNameExcludingId(
    name: string,
    excludeId: number,
    prismaClient?: PrismaTransactionClient,
  ): Promise<RoleType | null> {
    const client = this.getClient(prismaClient)
    return client.role.findFirst({
      where: {
        name: {
          equals: name,
          mode: 'insensitive',
        },
        id: {
          not: excludeId,
        },
        deletedAt: null,
      },
    })
  }

  async findById(id: number, prismaClient?: PrismaTransactionClient): Promise<RoleWithPermissionsType | null> {
    const client = this.getClient(prismaClient)
    return client.role.findUnique({
      where: {
        id,
        deletedAt: null,
      },
      include: {
        permissions: {
          where: { deletedAt: null },
        },
      },
    })
  }

  async create(
    { createdById, data }: { createdById: number | null; data: CreateRoleBodyType },
    prismaClient?: PrismaTransactionClient,
  ): Promise<RoleType> {
    const client = this.getClient(prismaClient)
    return client.role.create({
      data: {
        ...data,
        createdById,
      },
    })
  }

  async update(id: string | number, data: any, prismaClient?: PrismaTransactionClient): Promise<RoleType> {
    const client = this.getClient(prismaClient)

    // Kiểm tra nếu có bất cứ permissionId nào mà đã soft delete thì không cho phép cập nhật
    if (data.permissionIds && data.permissionIds.length > 0) {
      const permissions = await client.permission.findMany({
        where: {
          id: {
            in: data.permissionIds,
          },
        },
      })
      const deletedPermission = permissions.filter((permission) => permission.deletedAt)
      if (deletedPermission.length > 0) {
        const deletedIds = deletedPermission.map((permission) => permission.id).join(', ')
        throw new Error(`Permission with id has been deleted: ${deletedIds}`)
      }
    }

    return client.role.update({
      where: {
        id: Number(id),
        deletedAt: null,
      },
      data: {
        name: data.name,
        description: data.description,
        isActive: data.isActive,
        permissions: data.permissionIds
          ? {
              set: data.permissionIds.map((id: number) => ({ id })),
            }
          : undefined,
        updatedById: data.updatedById,
      },
      include: {
        permissions: {
          where: {
            deletedAt: null,
          },
        },
      },
    })
  }

  async delete(id: string | number, data: any, prismaClient?: PrismaTransactionClient): Promise<RoleType> {
    const client = this.getClient(prismaClient)
    return client.role.update({
      where: {
        id: Number(id),
        deletedAt: null,
      },
      data: {
        deletedAt: new Date(),
        deletedById: data.deletedById,
      },
    })
  }

  async updateRoleWithPermissions(
    id: number,
    updatedById: number,
    data: UpdateRoleBodyType,
    prismaClient?: PrismaTransactionClient,
  ): Promise<RoleType> {
    return this.update(id, { ...data, updatedById }, prismaClient)
  }

  async softDeleteRole(id: number, deletedById: number, prismaClient?: PrismaTransactionClient): Promise<RoleType> {
    const client = this.getClient(prismaClient)
    return client.role.update({
      where: {
        id,
        deletedAt: null,
      },
      data: {
        deletedAt: new Date(),
        deletedById,
      },
    })
  }

  async hardDeleteRole(id: number, prismaClient?: PrismaTransactionClient): Promise<RoleType> {
    const client = this.getClient(prismaClient)
    return client.role.delete({
      where: { id },
    })
  }
}
