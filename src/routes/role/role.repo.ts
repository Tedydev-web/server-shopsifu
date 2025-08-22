import { Injectable } from '@nestjs/common'
import {
  CreateRoleBodyType,
  GetRolesResType,
  RoleWithPermissionsType,
  UpdateRoleBodyType
} from 'src/routes/role/role.model'
import { RoleType } from 'src/shared/models/shared-role.model'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class RoleRepo {
  constructor(private prismaService: PrismaService) {}

  async list({ page, limit, name }: { page: number; limit: number; name?: string }): Promise<GetRolesResType> {
    const skip = (page - 1) * limit
    const take = limit

    const where: any = {
      deletedAt: null
    }

    // Thêm filter theo name nếu có
    if (name) {
      where.name = {
        contains: name,
        mode: 'insensitive'
      }
    }

    const [totalItems, data] = await Promise.all([
      this.prismaService.role.count({
        where
      }),
      this.prismaService.role.findMany({
        where,
        skip,
        take
      })
    ])
    return {
      data,
      metadata: {
        totalItems,
        page,
        limit,
        totalPages: Math.ceil(totalItems / limit),
        hasNext: page < Math.ceil(totalItems / limit),
        hasPrev: page > 1
      }
    }
  }

  findById(id: string): Promise<RoleWithPermissionsType | null> {
    return this.prismaService.role.findUnique({
      where: {
        id,
        deletedAt: null
      },
      include: {
        permissions: {
          where: {
            deletedAt: null
          }
        }
      }
    })
  }

  create({ createdById, data }: { createdById: string | null; data: CreateRoleBodyType }): Promise<RoleType> {
    return this.prismaService.role.create({
      data: {
        ...data,
        createdById
      }
    })
  }

  async update({
    id,
    updatedById,
    data
  }: {
    id: string
    updatedById: string
    data: UpdateRoleBodyType
  }): Promise<RoleType> {
    // Kiểm tra nếu có bất cứ permissionId nào mà đã soft delete thì không cho phép cập nhật
    if (data.permissionIds.length > 0) {
      const permissions = await this.prismaService.permission.findMany({
        where: {
          id: {
            in: data.permissionIds
          }
        }
      })
      const deletedPermission = permissions.filter((permission) => permission.deletedAt)
      if (deletedPermission.length > 0) {
        const deletedIds = deletedPermission.map((permission) => permission.id).join(', ')
        throw new Error(`Permission with id has been deleted: ${deletedIds}`)
      }
    }

    return this.prismaService.role.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        name: data.name,
        description: data.description,
        isActive: data.isActive,
        permissions: {
          set: data.permissionIds.map((id) => ({ id }))
        },
        updatedById
      },
      include: {
        permissions: {
          where: {
            deletedAt: null
          }
        }
      }
    })
  }

  delete(
    {
      id,
      deletedById
    }: {
      id: string
      deletedById: string
    },
    isHard?: boolean
  ): Promise<RoleType> {
    return isHard
      ? this.prismaService.role.delete({
          where: {
            id
          }
        })
      : this.prismaService.role.update({
          where: {
            id,
            deletedAt: null
          },
          data: {
            deletedAt: new Date(),
            deletedById
          }
        })
  }
}
