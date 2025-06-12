import { Injectable, Logger } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { ALL_PERMISSIONS_CACHE_TTL, PERMISSION_CACHE_TTL } from 'src/shared/providers/redis/redis.constants'
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { PrismaService } from 'src/shared/providers/prisma/prisma.service'
import { Permission } from './permission.model'

export type CreatePermissionData = Omit<Prisma.PermissionCreateInput, 'createdBy' | 'updatedBy' | 'deletedBy'>
export type UpdatePermissionData = Omit<Prisma.PermissionUpdateInput, 'createdBy' | 'updatedBy' | 'deletedBy'>
@Injectable()
export class PermissionRepository {
  private readonly logger = new Logger(PermissionRepository.name)
  constructor(
    private readonly prisma: PrismaService,
    private readonly redisService: RedisService
  ) {}

  private async invalidatePermissionCache(permission?: Permission | null): Promise<void> {
    const keysToDel: string[] = [RedisKeyManager.getAllPermissionsCacheKey()]
    if (permission) {
      keysToDel.push(RedisKeyManager.getPermissionCacheKey(permission.id))
      keysToDel.push(RedisKeyManager.getPermissionByActionAndSubjectCacheKey(permission.action, permission.subject))
    }
    await this.redisService.del(keysToDel)
    this.logger.debug(`Invalidated permission cache for keys: ${keysToDel.join(', ')}`)
  }

  async create(data: CreatePermissionData): Promise<Permission> {
    const newPermission = await this.prisma.permission.create({
      data
    })
    if (newPermission) {
      await this.invalidatePermissionCache()
    }
    return newPermission
  }

  async findAll(page?: number, limit?: number): Promise<Permission[]> {
    // If pagination parameters are provided, don't use cache and return paginated results
    if (page !== undefined && limit !== undefined) {
      const offset = (page - 1) * limit
      return this.prisma.permission.findMany({
        skip: offset,
        take: limit,
        orderBy: {
          id: 'desc'
        }
      })
    }

    // For non-paginated requests, use cache
    const cacheKey = RedisKeyManager.getAllPermissionsCacheKey()
    const cachedPermissions = await this.redisService.getJson<Permission[]>(cacheKey)
    if (cachedPermissions) {
      this.logger.debug('findAll permissions from cache')
      return cachedPermissions
    }

    const permissions = await this.prisma.permission.findMany({
      orderBy: {
        id: 'desc'
      }
    })
    await this.redisService.setJson(cacheKey, permissions, ALL_PERMISSIONS_CACHE_TTL)
    return permissions
  }

  async count(): Promise<number> {
    return this.prisma.permission.count()
  }

  async findById(id: number): Promise<Permission | null> {
    const cacheKey = RedisKeyManager.getPermissionCacheKey(id)
    const cachedPermission = await this.redisService.getJson<Permission>(cacheKey)
    if (cachedPermission) {
      this.logger.debug(`findById permission ${id} from cache`)
      return cachedPermission
    }
    const permission = await this.prisma.permission.findUnique({
      where: { id }
    })
    if (permission) {
      await this.redisService.setJson(cacheKey, permission, PERMISSION_CACHE_TTL)
    }
    return permission
  }

  async findByActionAndSubject(action: string, subject: string): Promise<Permission | null> {
    const cacheKey = RedisKeyManager.getPermissionByActionAndSubjectCacheKey(action, subject)
    const cachedPermission = await this.redisService.getJson<Permission>(cacheKey)
    if (cachedPermission) {
      this.logger.debug(`findByActionAndSubject permission ${action}/${subject} from cache`)
      return cachedPermission
    }
    const permission = await this.prisma.permission.findUnique({
      where: { action_subject: { action, subject } }
    })
    if (permission) {
      await this.redisService.setJson(cacheKey, permission, PERMISSION_CACHE_TTL)
    }
    return permission
  }

  async update(id: number, data: UpdatePermissionData): Promise<Permission> {
    const updatedPermission = await this.prisma.permission.update({
      where: { id },
      data
    })
    if (updatedPermission) {
      await this.invalidatePermissionCache(updatedPermission)
    }
    return updatedPermission
  }

  async remove(id: number): Promise<Permission> {
    const permissionToDelete = await this.findById(id)
    const deletedPermission = await this.prisma.permission.delete({
      where: { id }
    })
    if (deletedPermission) {
      await this.invalidatePermissionCache(permissionToDelete)
    }
    return deletedPermission
  }
}
