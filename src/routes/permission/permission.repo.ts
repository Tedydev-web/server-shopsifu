import { Injectable } from '@nestjs/common'
import {
  CreatePermissionBodyType,
  GetPermissionsQueryType,
  UpdatePermissionBodyType,
} from 'src/routes/permission/permission.model'
import { PermissionType } from 'src/shared/models/shared-permission.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { HTTPMethod } from '@prisma/client'
import { PaginationService, PaginatedResult } from 'src/shared/services/pagination.service'

@Injectable()
export class PermissionRepo {
  constructor(
    private prismaService: PrismaService,
    private paginationService: PaginationService,
  ) {}

  list(pagination: GetPermissionsQueryType): Promise<PaginatedResult<PermissionType>> {
    const { module, ...rest } = pagination
    const where: any = { deletedAt: null }
    if (module) {
      where.module = module
    }
    return this.paginationService.paginate('permission', rest, where, {
      searchableFields: ['id', 'name', 'path', 'module'],
      cursorFields: ['id'],
      orderBy: [{ createdAt: 'desc' }],
    })
  }

  findAll(): Promise<PermissionType[]> {
    return this.prismaService.permission.findMany({
      where: { deletedAt: null },
      orderBy: [{ module: 'asc' }, { name: 'asc' }],
    })
  }

  findById(id: number): Promise<PermissionType | null> {
    return this.prismaService.permission.findUnique({
      where: {
        id,
        deletedAt: null,
      },
    })
  }

  create({
    createdById,
    data,
  }: {
    createdById: number | null
    data: CreatePermissionBodyType
  }): Promise<PermissionType> {
    return this.prismaService.permission.create({
      data: {
        ...data,
        createdById,
      },
    })
  }

  async update({
    id,
    updatedById,
    data,
  }: {
    id: number
    updatedById: number
    data: UpdatePermissionBodyType
  }): Promise<PermissionType> {
    return this.prismaService.permission.update({
      where: {
        id,
        deletedAt: null,
      },
      data: {
        ...data,
        updatedById,
      },
    })
  }

  delete(
    {
      id,
      deletedById,
    }: {
      id: number
      deletedById: number
    },
    isHard?: boolean,
  ): Promise<PermissionType> {
    return isHard
      ? this.prismaService.permission.delete({
          where: {
            id,
          },
        })
      : this.prismaService.permission.update({
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

  isExisted(path: string, method: string): Promise<PermissionType | null> {
    return this.prismaService.permission.findFirst({
      where: {
        path,
        method: method as HTTPMethod,
        deletedAt: null,
      },
    })
  }
}
