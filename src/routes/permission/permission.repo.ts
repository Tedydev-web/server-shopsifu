import { Injectable } from '@nestjs/common'
import {
  CreatePermissionBodyType,
  GetPermissionsQueryType,
  GetPermissionsResType,
  PermissionType,
  UpdatePermissionBodyType
} from 'src/routes/permission/permission.model'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class PermissionRepo {
  constructor(private prismaService: PrismaService) {}

  async list(pagination: GetPermissionsQueryType): Promise<GetPermissionsResType> {
    const skip = (pagination.page - 1) * pagination.limit
    const take = pagination.limit
    const [totalItems, data] = await Promise.all([
      this.prismaService.permission.count({
        where: {
          deletedAt: null
        }
      }),
      this.prismaService.permission.findMany({
        where: {
          deletedAt: null
        },
        skip,
        take
      })
    ])
    return {
      data,
      metadata: {
        totalItems,
        page: pagination.page,
        limit: pagination.limit,
        totalPages: Math.ceil(totalItems / pagination.limit),
        hasNext: pagination.page < Math.ceil(totalItems / pagination.limit),
        hasPrev: pagination.page > 1
      }
    }
  }

  findById(id: string): Promise<PermissionType | null> {
    return this.prismaService.permission.findUnique({
      where: {
        id,
        deletedAt: null
      }
    })
  }

  create({
    createdById,
    data
  }: {
    createdById: string | null
    data: CreatePermissionBodyType
  }): Promise<PermissionType> {
    return this.prismaService.permission.create({
      data: {
        ...data,
        createdById
      }
    })
  }

  update({
    id,
    updatedById,
    data
  }: {
    id: string
    updatedById: string
    data: UpdatePermissionBodyType
  }): Promise<PermissionType & { roles: { id: string }[] }> {
    return this.prismaService.permission.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        ...data,
        updatedById
      },
      include: {
        roles: true
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
  ): Promise<PermissionType & { roles: { id: string }[] }> {
    return isHard
      ? this.prismaService.permission.delete({
          where: {
            id
          },
          include: {
            roles: true
          }
        })
      : this.prismaService.permission.update({
          where: {
            id,
            deletedAt: null
          },
          data: {
            deletedAt: new Date(),
            deletedById
          },
          include: {
            roles: true
          }
        })
  }
}
