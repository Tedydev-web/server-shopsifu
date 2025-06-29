import { Injectable } from '@nestjs/common'

import { PrismaService } from 'src/shared/services/prisma.service'
import { PermissionPaginationQueryType, PaginatedResponseType } from 'src/routes/permission/permission.model'
import { CreatePermissionBodyType, PermissionType } from './permission.model'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'

@Injectable()
export class PermissionRepo extends BaseRepository<PermissionType> {
  constructor(prismaService: PrismaService) {
    super(prismaService, 'permission')
  }

  protected getSearchableFields(): string[] {
    return ['name', 'description', 'path']
  }

  protected getSortableFields(): string[] {
    return ['id', 'name', 'path', 'method', 'createdAt', 'updatedAt']
  }

  async findAllWithPagination(query: PermissionPaginationQueryType): Promise<PaginatedResponseType<PermissionType>> {
    return this.paginate(query, { deletedAt: null })
  }

  async findById(id: number, prismaClient?: PrismaTransactionClient): Promise<PermissionType | null> {
    const client = this.getClient(prismaClient)
    return client.permission.findUnique({
      where: {
        id,
        deletedAt: null,
      },
    })
  }

  async create(
    { createdById, data }: { createdById: number | null; data: CreatePermissionBodyType },
    prismaClient?: PrismaTransactionClient,
  ): Promise<PermissionType> {
    const client = this.getClient(prismaClient)
    return client.permission.create({
      data: {
        ...data,
        createdById,
        updatedById: createdById,
      },
    })
  }

  async update(id: string | number, data: any, prismaClient?: PrismaTransactionClient): Promise<PermissionType> {
    const client = this.getClient(prismaClient)
    return client.permission.update({
      where: {
        id: Number(id),
        deletedAt: null,
      },
      data: {
        ...data,
        updatedById: data.updatedById,
      },
    })
  }

  async delete(id: string | number, data: any, prismaClient?: PrismaTransactionClient): Promise<PermissionType> {
    const client = this.getClient(prismaClient)
    return client.permission.update({
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

  async updatePermission(
    id: number,
    updatedById: number,
    data: CreatePermissionBodyType,
    prismaClient?: PrismaTransactionClient,
  ): Promise<PermissionType> {
    return this.update(id, { ...data, updatedById }, prismaClient)
  }

  async softDeletePermission(
    id: number,
    deletedById: number,
    prismaClient?: PrismaTransactionClient,
  ): Promise<PermissionType> {
    const client = this.getClient(prismaClient)
    return client.permission.update({
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
}
