import { Injectable } from '@nestjs/common'
import {
  CreatePermissionBodyType,
  PermissionType,
  UpdatePermissionBodyType,
  GetPermissionsQueryType,
  HTTPMethod,
  HTTPMethodType
} from 'src/routes/permission/permission.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma } from '@prisma/client'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { CacheService } from 'src/shared/services/cache.service'

@Injectable()
export class PermissionRepo extends BaseRepository<PermissionType> {
  constructor(
    protected readonly prismaService: PrismaService,
    private readonly cacheService: CacheService
  ) {
    super(prismaService, PermissionRepo.name)
  }

  async findAll(
    query?: GetPermissionsQueryType,
    prismaClient?: PrismaTransactionClient
  ): Promise<{ permissions: PermissionType[]; totalItems: number }> {
    const {
      page = 1,
      limit = 10,
      sortBy = 'createdAt',
      sortOrder = 'desc',
      search = '',
      includeDeleted = false,
      method,
      startDate,
      endDate,
      all = false
    } = query || {}

    const where: any = {}

    if (search) {
      where.OR = this.getSearchableFields().map((field) => ({
        [field]: { contains: search, mode: 'insensitive' }
      }))
    }

    if (!includeDeleted) {
      where.deletedAt = null
    }

    if (method) {
      where.method = method
    }

    if (startDate || endDate) {
      where.createdAt = {}
      if (startDate) where.createdAt.gte = new Date(startDate)
      if (endDate) where.createdAt.lte = new Date(endDate)
    }

    const shouldCache = !all && limit <= 100
    const cacheKey = shouldCache
      ? `permissions:list:${page}:${limit}:${sortBy}:${sortOrder}:${search}:${includeDeleted}:${method || ''}:${startDate || ''}:${endDate || ''}:${all}`
      : null

    const effectiveLimit = all ? 1000 : limit

    if (shouldCache && cacheKey) {
      return this.cacheService.getOrSet(
        cacheKey,
        async () => {
          const result = await this.paginateQuery<PermissionType>(
            'permission',
            {
              page,
              limit: effectiveLimit,
              sortBy,
              sortOrder,
              search
            },
            where,
            {},
            prismaClient
          )

          return {
            permissions: result.data,
            totalItems: result.totalItems
          }
        },
        30000
      )
    }

    const result = await this.paginateQuery<PermissionType>(
      'permission',
      {
        page,
        limit: effectiveLimit,
        sortBy,
        sortOrder,
        search
      },
      where,
      {},
      prismaClient
    )

    return {
      permissions: result.data,
      totalItems: result.totalItems
    }
  }

  async findById(
    id: number,
    includeDeleted: boolean = false,
    prismaClient?: PrismaTransactionClient
  ): Promise<PermissionType | null> {
    const client = this.getClient(prismaClient)

    const cacheKey = `permission:${id}:${includeDeleted}`

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        const where: Prisma.PermissionWhereUniqueInput = { id }
        if (!includeDeleted) {
          where.deletedAt = null as any
        }
        return client.permission.findUnique({ where })
      },
      30000
    )
  }

  async findByPathAndMethod(
    path: string,
    method: HTTPMethodType,
    includeDeleted: boolean = false,
    prismaClient?: PrismaTransactionClient
  ): Promise<PermissionType | null> {
    const client = this.getClient(prismaClient)

    const cacheKey = `permission:path:${path}:method:${method}:${includeDeleted}`

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        const where: Prisma.PermissionWhereInput = {
          path,
          method
        }
        if (!includeDeleted) {
          where.deletedAt = null
        }
        return client.permission.findFirst({ where })
      },
      30000
    )
  }

  async create(
    { createdById, data }: { createdById: number; data: CreatePermissionBodyType },
    prismaClient?: PrismaTransactionClient
  ): Promise<PermissionType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Creating permission: ${JSON.stringify(data)}`)

    const result = await client.permission.create({
      data: {
        ...data,
        createdById
      }
    })

    this.cacheService.invalidate('permissions:list')

    return result
  }

  async update(
    {
      id,
      updatedById,
      data
    }: {
      id: number
      updatedById: number
      data: UpdatePermissionBodyType
    },
    prismaClient?: PrismaTransactionClient
  ): Promise<PermissionType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Updating permission ${id}: ${JSON.stringify(data)}`)

    const result = await client.permission.update({
      where: {
        id,
        deletedAt: null as any
      },
      data: {
        ...data,
        updatedById
      }
    })

    this.cacheService.invalidate(`permission:${id}`)
    this.cacheService.invalidate('permissions:list')

    return result
  }

  async softDelete(id: number, deletedById: number, prismaClient?: PrismaTransactionClient): Promise<PermissionType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Soft deleting permission: ${id}`)

    const result = await client.permission.update({
      where: {
        id,
        deletedAt: null as any
      },
      data: {
        deletedAt: new Date(),
        deletedById
      }
    })

    this.cacheService.invalidate(`permission:${id}`)
    this.cacheService.invalidate('permissions:list')

    return result
  }

  async hardDelete(id: number, prismaClient?: PrismaTransactionClient): Promise<PermissionType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Hard deleting permission: ${id}`)

    const result = await client.permission.delete({
      where: { id }
    })

    this.cacheService.invalidate(`permission:${id}`)
    this.cacheService.invalidate('permissions:list')

    return result
  }

  async restore(id: number, updatedById: number, prismaClient?: PrismaTransactionClient): Promise<PermissionType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Restoring permission: ${id}`)

    const result = await client.permission.update({
      where: {
        id,
        NOT: {
          deletedAt: null
        }
      },
      data: {
        deletedAt: null,
        updatedById
      }
    })

    this.cacheService.invalidate(`permission:${id}`)
    this.cacheService.invalidate('permissions:list')

    return result
  }

  async countRoles(id: number, prismaClient?: PrismaTransactionClient): Promise<number> {
    const client = this.getClient(prismaClient)

    const cacheKey = `permission:${id}:roles`

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        const permission = await client.permission.findUnique({
          where: { id },
          include: { roles: { select: { id: true } } }
        })
        return permission?.roles.length || 0
      },
      60000
    )
  }

  protected getSearchableFields(): string[] {
    return ['name', 'description', 'path']
  }
}
