import { Injectable, Inject } from '@nestjs/common'
import {
  CreatePermissionBodyType,
  PermissionType,
  UpdatePermissionBodyType,
  GetPermissionsQueryType,
  HTTPMethodType
} from 'src/routes/permission/permission.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma } from '@prisma/client'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { CACHE_MANAGER, Cache } from '@nestjs/cache-manager'
import { RedisService } from 'src/shared/providers/redis/redis.service'

@Injectable()
export class PermissionRepo extends BaseRepository<PermissionType> {
  constructor(
    protected readonly prismaService: PrismaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly redisService: RedisService
  ) {
    super(prismaService, PermissionRepo.name)
  }

  private async invalidatePermissionItemCache(id: number) {
    await this.cacheManager.del(`permission:${id}`)
    await this.cacheManager.del(`permission:${id}:includeDeleted`)
    await this.invalidateAllPermissionListsCache()
  }

  private async invalidateAllPermissionListsCache() {
    this.logger.debug('Invalidating all permission list caches with pattern permission:list:*')
    try {
      const pattern = 'permission:list:*'
      const keys = await this.redisService.findKeys(pattern)
      if (keys.length > 0) {
        await this.redisService.del(keys)
        this.logger.debug(`Invalidated ${keys.length} permission list cache keys matching pattern ${pattern}.`)
      } else {
        this.logger.debug(`No permission list cache keys found to invalidate with pattern ${pattern}.`)
      }
    } catch (error) {
      this.logger.error('Error invalidating permission list caches:', error)
    }
  }

  async findAll(
    query?: GetPermissionsQueryType,
    prismaClient?: PrismaTransactionClient
  ): Promise<{ permissions: PermissionType[]; totalItems: number }> {
    const client = this.getClient(prismaClient)
    const {
      page = 1,
      limit = 10,
      sortBy = 'id',
      sortOrder = 'asc',
      search = '',
      includeDeleted = false,
      all = false
    } = query || {}

    const where: Prisma.PermissionWhereInput = {}
    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { path: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } }
      ]
    }
    if (!includeDeleted) {
      where.deletedAt = null
    }

    const effectiveLimit = all ? 10000 : limit // Allow fetching more if 'all' is true, up to a reasonable max
    const cacheKey = `permissions:list:${page}:${effectiveLimit}:${sortBy}:${sortOrder}:${search}:${includeDeleted}:${all}`

    const cachedResult = await this.cacheManager.get<{ permissions: PermissionType[]; totalItems: number }>(cacheKey)
    if (cachedResult) return cachedResult

    const permissionsPromise = client.permission.findMany({
      where,
      skip: all ? undefined : (page - 1) * limit,
      take: effectiveLimit,
      orderBy: { [sortBy]: sortOrder }
    })
    const totalItemsPromise = client.permission.count({ where })

    const [permissions, totalItems] = await Promise.all([permissionsPromise, totalItemsPromise])

    await this.cacheManager.set(cacheKey, { permissions, totalItems }, 60000)
    return { permissions, totalItems }
  }

  async findById(
    id: number,
    includeDeleted: boolean = false,
    prismaClient?: PrismaTransactionClient
  ): Promise<PermissionType | null> {
    const client = this.getClient(prismaClient)
    const cacheKey = `permission:${id}${includeDeleted ? ':includeDeleted' : ''}`
    const cachedPermission = await this.cacheManager.get<PermissionType | null>(cacheKey)
    if (cachedPermission !== undefined) return cachedPermission

    const permission = await client.permission.findUnique({
      where: { id, ...(includeDeleted ? {} : { deletedAt: null }) }
    })
    await this.cacheManager.set(cacheKey, permission, 300000)
    return permission
  }

  async findByPathAndMethod(
    path: string,
    method: HTTPMethodType,
    includeDeleted: boolean = false,
    prismaClient?: PrismaTransactionClient
  ): Promise<PermissionType | null> {
    const client = this.getClient(prismaClient)
    const cacheKey = `permission:path:${path}:method:${method}:${includeDeleted}`

    const cachedPermission = await this.cacheManager.get<PermissionType | null>(cacheKey)
    if (cachedPermission !== undefined) {
      return cachedPermission
    }

        const where: Prisma.PermissionWhereInput = {
          path,
          method
        }
        if (!includeDeleted) {
          where.deletedAt = null
        }
    const permission = await client.permission.findFirst({ where })
    await this.cacheManager.set(cacheKey, permission, 30000) // TTL from original getOrSet
    return permission
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

    await this.invalidateAllPermissionListsCache()

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

    await this.invalidatePermissionItemCache(id)

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

    await this.invalidatePermissionItemCache(id)

    return result
  }

  async hardDelete(id: number, prismaClient?: PrismaTransactionClient): Promise<PermissionType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Hard deleting permission: ${id}`)

    const result = await client.permission.delete({
      where: { id }
    })

    await this.invalidatePermissionItemCache(id)

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

    await this.invalidatePermissionItemCache(id)

    return result
  }

  async countRoles(id: number, prismaClient?: PrismaTransactionClient): Promise<number> {
    const client = this.getClient(prismaClient)
    const cacheKey = `permission:${id}:roles`

    const cachedCount = await this.cacheManager.get<number>(cacheKey)
    if (cachedCount !== undefined && cachedCount !== null) {
      return cachedCount
    }

        const permission = await client.permission.findUnique({
          where: { id },
          include: { roles: { select: { id: true } } }
        })
    const count = permission?.roles.length || 0
    await this.cacheManager.set(cacheKey, count, 60000) // TTL from original getOrSet
    return count
  }

  protected getSearchableFields(): string[] {
    return ['name', 'description', 'path']
  }
}
