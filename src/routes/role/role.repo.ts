import { Injectable } from '@nestjs/common'
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
import { CacheService } from 'src/shared/services/cache.service'
import { PaginatedResponseType } from 'src/shared/models/pagination.model'

@Injectable()
export class RoleRepo extends BaseRepository<RoleType> {
  protected readonly shortCacheTTL = 1000 * 10 // 10 seconds
  protected readonly mediumCacheTTL = 1000 * 60 * 5 // 5 minutes
  protected readonly longCacheTTL = 1000 * 60 * 30 // 30 minutes

  constructor(
    protected readonly prismaService: PrismaService,
    private readonly cacheService: CacheService
  ) {
    super(prismaService, RoleRepo.name)
  }

  private getRoleCacheKey(id: number | string, includeDeleted: boolean = false) {
    return `role:${id}:${includeDeleted}`
  }

  private invalidateRoleListCache() {
    this.cacheService.invalidate('roles:list')
  }

  private invalidateRoleCache(id: number) {
    this.cacheService.invalidate(this.getRoleCacheKey(id))
    this.cacheService.invalidate(this.getRoleCacheKey(id, true))
    this.invalidateRoleListCache()
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

    const cacheKey = `roles:list:${page}:${limit}:${sortBy}:${sortOrder}:${search}:${includeDeleted}:${isActive}:${permissionIds?.join('-')}:${all}`
    const effectiveLimit = all ? 1000 : limit

    const ttl = shouldCache(query) ? this.mediumCacheTTL : 0

    const paginatedResult = await this.cacheService.getOrSet(
      cacheKey,
      () =>
        this.paginateQuery<RoleType>(
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
        ),
      ttl
    )
    return paginatedResult
  }

  async findById(
    id: number,
    includeDeleted: boolean = false,
    prismaClient?: PrismaTransactionClient
  ): Promise<RoleType | null> {
    const client = this.getClient(prismaClient)
    const cacheKey = this.getRoleCacheKey(id, includeDeleted)

    return this.cacheService.getOrSet(
      cacheKey,
      () => {
        const whereClause: Prisma.RoleWhereUniqueInput = { id }
        if (!includeDeleted) {
          return client.role.findFirst({ where: { id, deletedAt: null }, include: { permissions: true } })
        }
        return client.role.findUnique({ where: whereClause, include: { permissions: true } })
      },
      this.mediumCacheTTL
    )
  }

  async findByName(name: string, prismaClient?: PrismaTransactionClient): Promise<RoleType | null> {
    const client = this.getClient(prismaClient)
    const cacheKey = `role:name:${name}`
    return this.cacheService.getOrSet(
      cacheKey,
      () => client.role.findFirst({ where: { name, deletedAt: null }, include: { permissions: true } }),
      this.mediumCacheTTL
    )
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

    const result = await client.role.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        ...roleData,
        updatedBy: { connect: { id: updatedById } },
        permissions: permissionIds ? { set: permissionIds.map((id) => ({ id })) } : undefined
      },
      include: { permissions: true }
    })
    this.invalidateRoleCache(id)
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
    return result
  }

  async hardDelete(id: number, prismaClient?: PrismaTransactionClient): Promise<RoleType> {
    const client = this.getClient(prismaClient)

    const result = await client.role.delete({ where: { id }, include: { permissions: true } })

    this.invalidateRoleCache(id)
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
        updatedById: updatedById
      },
      include: { permissions: true }
    })

    this.invalidateRoleCache(id)
    return result
  }

  async countUsers(id: number, prismaClient?: PrismaTransactionClient): Promise<number> {
    const client = this.getClient(prismaClient)
    const cacheKey = `role:${id}:users:count`
    return this.cacheService.getOrSet(
      cacheKey,
      () => client.user.count({ where: { roleId: id, deletedAt: null } }),
      this.longCacheTTL
    )
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
