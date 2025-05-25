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

@Injectable()
export class RoleRepo extends BaseRepository<RoleType> {
  protected readonly shortCacheTTL = 1000 * 10 // 10 seconds
  protected readonly mediumCacheTTL = 1000 * 60 * 5 // 5 minutes
  protected readonly longCacheTTL = 1000 * 60 * 30 // 30 minutes

  constructor(
    protected readonly prismaService: PrismaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache
  ) {
    super(prismaService, RoleRepo.name)
  }

  private getRoleCacheKey(id: number, includeDeleted: boolean = false): string {
    return `role:${id}${includeDeleted ? ':includeDeleted' : ''}`
  }

  private getRoleWithPermissionsCacheKey(id: number, includeDeleted: boolean = false): string {
    return `role:${id}:withPermissions${includeDeleted ? ':includeDeleted' : ''}`
  }

  private getRoleListCacheKey(query?: GetRolesQueryType): string {
    const {
      page = 1,
      limit = 10,
      sortBy = 'id',
      sortOrder = 'asc',
      search = '',
      includeDeleted = false,
      all = false
    } = query || {}
    const effectiveLimit = all ? 10000 : limit // Define effectiveLimit based on 'all' flag
    return `roles:list:${page}:${effectiveLimit}:${sortBy}:${sortOrder}:${search}:${includeDeleted}:${all}`
  }

  private getRoleByNameCacheKey(name: string): string {
    return `role:name:${name}`
  }

  private getRoleReferencesCountCacheKey(id: number): string {
    return `role:${id}:references:count`
  }

  private invalidateRoleListCache() {
    this.cacheManager.del('roles:list')
  }

  private invalidateRoleCache(id: number) {
    this.cacheManager.del(this.getRoleCacheKey(id))
    this.cacheManager.del(this.getRoleCacheKey(id, true))
    this.cacheManager.del(this.getRoleWithPermissionsCacheKey(id))
    this.cacheManager.del(this.getRoleWithPermissionsCacheKey(id, true))
    this.invalidateRoleListCache()
  }

  private invalidateRoleNameCache(name: string) {
    this.cacheManager.del(this.getRoleByNameCacheKey(name))
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

    this.invalidateRoleListCache()
    if (result.name) this.invalidateRoleNameCache(result.name)
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
    const { permissionIds, ...roleData } = data

    const currentRole = await client.role.findUnique({ where: { id } })
    if (currentRole && currentRole.name !== roleData.name && roleData.name) {
      this.invalidateRoleNameCache(currentRole.name)
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
    this.invalidateRoleCache(id)
    if (result.name) this.invalidateRoleNameCache(result.name)
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
    this.invalidateRoleCache(roleId)
    if (result.name) this.invalidateRoleNameCache(result.name)
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

    this.invalidateRoleCache(id)
    if (result.name) this.invalidateRoleNameCache(result.name)
    return result
  }

  async hardDelete(id: number, prismaClient?: PrismaTransactionClient): Promise<RoleType> {
    const client = this.getClient(prismaClient)

    const result = await client.role.delete({ where: { id }, include: { permissions: true } })

    this.invalidateRoleCache(id)
    if (result.name) this.invalidateRoleNameCache(result.name)
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

    this.invalidateRoleCache(id)
    if (result.name) this.invalidateRoleNameCache(result.name)
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
