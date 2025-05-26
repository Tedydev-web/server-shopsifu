import { Injectable, Inject } from '@nestjs/common'
import {
  CreateRoleBodyType,
  RoleType,
  UpdateRoleBodyType,
  GetRolesQueryType,
  AssignPermissionsToRoleBodyType
} from 'src/routes/role/role.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma } from '@prisma/client'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { CACHE_MANAGER, Cache } from '@nestjs/cache-manager'
import { PaginatedResponseType } from 'src/shared/models/pagination.model'
import { RedisService } from 'src/shared/providers/redis/redis.service'

@Injectable()
export class RoleRepo extends BaseRepository<RoleType> {
  protected readonly shortCacheTTL = 1000 * 10 // 10 seconds
  protected readonly mediumCacheTTL = 1000 * 60 * 5 // 5 minutes
  protected readonly longCacheTTL = 1000 * 60 * 30 // 30 minutes

  constructor(
    protected readonly prismaService: PrismaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly redisService: RedisService
  ) {
    super(prismaService, RoleRepo.name)
  }

  private getRoleCacheKey(id: number, includeDeleted: boolean = false): string {
    return `role:${id}:${includeDeleted ? 'withDeleted' : 'active'}`
  }

  private getRoleWithPermissionsCacheKey(id: number, includeDeleted: boolean = false): string {
    return `role:${id}:permissions:${includeDeleted ? 'withDeleted' : 'active'}`
  }

  private getRoleListCacheKey(query?: GetRolesQueryType): string {
    if (
      !query ||
      Object.keys(query).length === 0 ||
      (query.page === 1 &&
        query.limit === 10 &&
        !query.search &&
        !query.sortBy &&
        !query.sortOrder &&
        !query.isActive &&
        !query.all)
    ) {
      return 'role:list:default' // Default key for the first page with default params
    }
    const queryParams = new URLSearchParams()
    if (query.page) queryParams.append('page', query.page.toString())
    if (query.limit) queryParams.append('limit', query.limit.toString())
    if (query.sortBy) queryParams.append('sortBy', query.sortBy)
    if (query.sortOrder) queryParams.append('sortOrder', query.sortOrder)
    if (query.search) queryParams.append('search', query.search)
    if (query.isActive !== undefined) queryParams.append('isActive', query.isActive.toString())
    if (query.all) queryParams.append('all', query.all.toString())
    return `role:list:${queryParams.toString()}`
  }

  private getRoleByNameCacheKey(name: string): string {
    return `role:name:${name}`
  }

  private getRoleReferencesCountCacheKey(id: number): string {
    return `role:${id}:referencesCount`
  }

  private async invalidateRoleListCache() {
    this.logger.debug('Invalidating all role list caches with pattern role:list:*')
    try {
      const pattern = 'role:list:*' // Define the pattern directly
      const keys = await this.redisService.findKeys(pattern) // Use the defined pattern
      if (keys.length > 0) {
        await this.redisService.del(keys) // Use redisService.del to delete keys found
        this.logger.debug(`Invalidated ${keys.length} role list cache keys matching pattern ${pattern}.`)
      } else {
        this.logger.debug(`No role list cache keys found to invalidate with pattern ${pattern}.`)
      }
    } catch (error) {
      this.logger.error('Error invalidating role list caches:', error)
    }
  }

  private async invalidateRoleCache(id: number) {
    await this.cacheManager.del(this.getRoleCacheKey(id))
    await this.cacheManager.del(this.getRoleCacheKey(id, true))
    await this.cacheManager.del(this.getRoleWithPermissionsCacheKey(id))
    await this.cacheManager.del(this.getRoleWithPermissionsCacheKey(id, true))
    await this.invalidateRoleListCache()
  }

  private async invalidateRoleNameCache(name: string) {
    await this.cacheManager.del(this.getRoleByNameCacheKey(name))
  }

  async findAll(
    query?: GetRolesQueryType,
    prismaClient?: PrismaTransactionClient
  ): Promise<PaginatedResponseType<RoleType>> {
    const {
      page = 1,
      limit = 10,
      sortBy = 'createdAt',
      sortOrder = 'desc',
      search = '',
      includeDeleted = false,
      isActive,
      permissionIds,
      all = false
    } = query || {}

    const where: Prisma.RoleWhereInput = {}

    if (search) {
      where.OR = this.getSearchableFields().map((field) => ({
        [field]: { contains: search, mode: 'insensitive' }
      }))
    }

    if (!includeDeleted) {
      where.deletedAt = null
    }

    if (typeof isActive === 'boolean') {
      where.isActive = isActive
    }

    if (permissionIds && permissionIds.length > 0) {
      where.permissions = {
        some: {
          id: {
            in: permissionIds
          }
        }
      }
    }

    const cacheKey = this.getRoleListCacheKey(query)
    const effectiveLimit = all ? 1000 : limit

    const ttl = shouldCache(query) ? this.mediumCacheTTL : 0

    const paginatedResult = await this.cacheManager.get<PaginatedResponseType<RoleType>>(cacheKey)
    if (paginatedResult && ttl > 0) {
      return paginatedResult
    }

    const freshResult = await this.paginateQuery<RoleType>(
          'role',
          {
            page,
            limit: effectiveLimit,
            sortBy,
            sortOrder,
            search
          },
          where,
          { permissions: true },
          prismaClient
    )

    if (ttl > 0) {
      await this.cacheManager.set(cacheKey, freshResult, ttl)
    }
    return freshResult
  }

  async findById(
    id: number,
    includeDeleted: boolean = false,
    prismaClient?: PrismaTransactionClient
  ): Promise<RoleType | null> {
    const client = this.getClient(prismaClient)
    const cacheKey = this.getRoleCacheKey(id, includeDeleted)

    const cachedRole = await this.cacheManager.get<RoleType | null>(cacheKey)
    if (cachedRole !== undefined) return cachedRole

        const whereClause: Prisma.RoleWhereUniqueInput = { id }
        if (!includeDeleted) {
      whereClause.deletedAt = null
    }

    const role = await client.role.findUnique({
      where: whereClause,
      include: { permissions: true }
    })

    if (role) {
      await this.cacheManager.set(cacheKey, role, this.mediumCacheTTL)
    }

    return role
  }

  async findByName(name: string, prismaClient?: PrismaTransactionClient): Promise<RoleType | null> {
    const client = this.getClient(prismaClient)
    const cacheKey = this.getRoleByNameCacheKey(name)
    const cachedRole = await this.cacheManager.get<RoleType | null>(cacheKey)
    if (cachedRole !== undefined) return cachedRole

    const role = await client.role.findFirst({
      where: { name, deletedAt: null },
      include: { permissions: true }
    })

    if (role) {
      await this.cacheManager.set(cacheKey, role, this.mediumCacheTTL)
    }

    return role
  }

  async create(
    { createdById, data }: { createdById: number; data: CreateRoleBodyType },
    prismaClient?: PrismaTransactionClient
  ): Promise<RoleType> {
    const client = this.getClient(prismaClient)
    const { permissionIds, ...roleData } = data

    const result = await client.role.create({
      data: {
        ...roleData,
        createdBy: { connect: { id: createdById } },
        permissions:
          permissionIds && permissionIds.length > 0 ? { connect: permissionIds.map((id) => ({ id })) } : undefined
      },
      include: { permissions: true }
    })

    await this.invalidateRoleListCache()
    if (result.name) await this.invalidateRoleNameCache(result.name)
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
      data: UpdateRoleBodyType
    },
    prismaClient?: PrismaTransactionClient
  ): Promise<RoleType> {
    const client = this.getClient(prismaClient)
    const { ...roleData } = data // Removed permissionIds from here as it's handled by assignPermissions

    const currentRole = await client.role.findUnique({ where: { id } })
    if (currentRole && currentRole.name !== roleData.name && roleData.name) {
      await this.invalidateRoleNameCache(currentRole.name)
    }

    const result = await client.role.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        ...roleData,
        updatedBy: { connect: { id: updatedById } },
        updatedAt: new Date()
      },
      include: { permissions: true }
    })
    await this.invalidateRoleCache(id)
    if (result.name) await this.invalidateRoleNameCache(result.name)
    return result
  }

  async assignPermissions(
    {
      roleId,
      updatedById,
      data
    }: {
      roleId: number
      updatedById: number
      data: AssignPermissionsToRoleBodyType
    },
    prismaClient?: PrismaTransactionClient
  ): Promise<RoleType> {
    const client = this.getClient(prismaClient)

    const result = await client.role.update({
      where: {
        id: roleId,
        deletedAt: null
      },
      data: {
        permissions: { set: data.permissionIds.map((id) => ({ id })) },
        updatedBy: { connect: { id: updatedById } }
      },
      include: { permissions: true }
    })
    await this.invalidateRoleCache(roleId)
    if (result.name) await this.invalidateRoleNameCache(result.name)
    return result
  }

  async softDelete(id: number, deletedById: number, prismaClient?: PrismaTransactionClient): Promise<RoleType> {
    const client = this.getClient(prismaClient)

    const result = await client.role.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        deletedAt: new Date(),
        deletedBy: { connect: { id: deletedById } },
        updatedBy: { connect: { id: deletedById } }
      },
      include: { permissions: true }
    })

    await this.invalidateRoleCache(id)
    if (result.name) await this.invalidateRoleNameCache(result.name)
    return result
  }

  async hardDelete(id: number, prismaClient?: PrismaTransactionClient): Promise<RoleType> {
    const client = this.getClient(prismaClient)

    const result = await client.role.delete({ where: { id }, include: { permissions: true } })

    await this.invalidateRoleCache(id)
    if (result.name) await this.invalidateRoleNameCache(result.name)
    return result
  }

  async restore(id: number, updatedById: number, prismaClient?: PrismaTransactionClient): Promise<RoleType> {
    const client = this.getClient(prismaClient)

    const result = await client.role.update({
      where: {
        id,
        NOT: {
          deletedAt: null
        }
      },
      data: {
        deletedAt: null,
        deletedById: null,
        updatedById: updatedById,
        updatedAt: new Date()
      },
      include: { permissions: true }
    })

    await this.invalidateRoleCache(id)
    if (result.name) await this.invalidateRoleNameCache(result.name)
    return result
  }

  async countUsers(id: number, prismaClient?: PrismaTransactionClient): Promise<number> {
    const client = this.getClient(prismaClient)
    const cacheKey = this.getRoleReferencesCountCacheKey(id)

    const cachedCount = await this.cacheManager.get<number>(cacheKey)
    if (cachedCount !== undefined && cachedCount !== null) {
      return cachedCount
    }

    const count = await client.user.count({ where: { roleId: id, deletedAt: null } })
    await this.cacheManager.set(cacheKey, count, this.longCacheTTL)
    return count
  }

  protected getSearchableFields(): string[] {
    return ['name', 'description']
  }
}

const shouldCache = (query?: GetRolesQueryType) => {
  if (!query) return true
  const { all, limit } = query
  return !all && (limit ?? 10) <= 100
}
