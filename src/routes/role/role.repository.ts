import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Role } from './role.model'
import { CreateRoleDto, UpdateRoleDto } from './role.dto'
import { Permission, Role as PrismaRole } from '@prisma/client' // Import Permission for type casting
import { RedisService } from 'src/shared/services/redis.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { ALL_ROLES_CACHE_TTL, ROLE_CACHE_TTL } from 'src/shared/constants/redis.constants'

// Helper type for Prisma's return when including PermissionsOnRoles with Permission
type RoleWithPermissionsOnRoles = PrismaRole & {
  permissions: ({
    permission: Permission
  } & {
    roleId: number
    permissionId: number
    assignedAt: Date
    assignedById: number | null
  })[]
}

@Injectable()
export class RoleRepository {
  private readonly logger = new Logger(RoleRepository.name)
  constructor(
    private readonly prisma: PrismaService,
    private readonly redisService: RedisService
  ) {}

  private mapToRoleType(roleWithPor: RoleWithPermissionsOnRoles | null): Role | null {
    if (!roleWithPor) {
      return null
    }
    const { permissions, ...restOfRole } = roleWithPor
    return {
      ...restOfRole,
      permissions: permissions.map((por) => por.permission)
    }
  }

  private async invalidateRoleCache(role?: Role | null): Promise<void> {
    const keysToDel: string[] = [RedisKeyManager.getAllRolesCacheKey()]
    if (role) {
      keysToDel.push(RedisKeyManager.getRoleCacheKey(role.id))
      keysToDel.push(RedisKeyManager.getRoleByNameCacheKey(role.name))
    }
    await this.redisService.del(keysToDel)
    this.logger.debug(`Invalidated role cache for keys: ${keysToDel.join(', ')}`)
  }

  async create(createRoleDto: CreateRoleDto): Promise<Role> {
    const { name, description, isSystemRole, permissionIds } = createRoleDto
    const createdRoleWithPor = await this.prisma.role.create({
      data: {
        name,
        description,
        isSystemRole: isSystemRole ?? false,
        permissions: permissionIds?.length
          ? {
              create: permissionIds.map((pid) => ({
                permission: { connect: { id: pid } }
                // assignedById: userId, // You might want to set this if available
              }))
            }
          : undefined
      },
      include: {
        permissions: { include: { permission: true } }
      }
    })

    const createdRole = this.mapToRoleType(createdRoleWithPor)
    if (createdRole) {
      await this.invalidateRoleCache()
    }
    return createdRole
  }

  async findAll(): Promise<Role[]> {
    const cacheKey = RedisKeyManager.getAllRolesCacheKey()
    const cachedRoles = await this.redisService.getJson<Role[]>(cacheKey)
    if (cachedRoles) {
      this.logger.debug('findAll roles from cache')
      return cachedRoles
    }

    const rolesWithPor = await this.prisma.role.findMany({
      include: {
        permissions: { include: { permission: true } }
      }
    })
    const roles = rolesWithPor.map((role) => this.mapToRoleType(role))
    await this.redisService.setJson(cacheKey, roles, ALL_ROLES_CACHE_TTL)
    return roles
  }

  async findById(id: number): Promise<Role | null> {
    const cacheKey = RedisKeyManager.getRoleCacheKey(id)
    const cachedRole = await this.redisService.getJson<Role>(cacheKey)
    if (cachedRole) {
      this.logger.debug(`findById role ${id} from cache`)
      return cachedRole
    }

    const roleWithPor = await this.prisma.role.findUnique({
      where: { id },
      include: {
        permissions: { include: { permission: true } }
      }
    })
    const role = this.mapToRoleType(roleWithPor)
    if (role) {
      await this.redisService.setJson(cacheKey, role, ROLE_CACHE_TTL)
    }
    return role
  }

  async findByName(name: string): Promise<Role | null> {
    const cacheKey = RedisKeyManager.getRoleByNameCacheKey(name)
    const cachedRole = await this.redisService.getJson<Role>(cacheKey)
    if (cachedRole) {
      this.logger.debug(`findByName role ${name} from cache`)
      return cachedRole
    }

    const roleWithPor = await this.prisma.role.findUnique({
      where: { name },
      include: {
        permissions: {
          include: {
            permission: true
          }
        }
      }
    })

    const role = this.mapToRoleType(roleWithPor)
    if (role) {
      await this.redisService.setJson(cacheKey, role, ROLE_CACHE_TTL)
      await this.redisService.setJson(RedisKeyManager.getRoleCacheKey(role.id), role, ROLE_CACHE_TTL)
    }
    return role
  }

  async update(id: number, updateRoleDto: UpdateRoleDto): Promise<Role> {
    const { name, description, isSystemRole, permissionIds } = updateRoleDto
    const dataToUpdate: any = {} // This disable is needed for flexible dataToUpdate object
    if (name !== undefined) dataToUpdate.name = name
    if (description !== undefined) dataToUpdate.description = description
    if (isSystemRole !== undefined) dataToUpdate.isSystemRole = isSystemRole

    if (permissionIds !== undefined) {
      // For many-to-many with explicit join table, updating permissions typically involves:
      // 1. Deleting existing join records for this role.
      // 2. Creating new join records for the new set of permissionIds.
      // This is done in a transaction to ensure atomicity.
      // Prisma's nested writes can simplify this if structured correctly.
      dataToUpdate.permissions = {
        deleteMany: { roleId: id }, // Delete all existing PermissionsOnRoles for this role
        create: permissionIds.map((pid) => ({
          permission: { connect: { id: pid } }
          // assignedById: userId, // Set if available and needed
        }))
      }
    }

    const updatedRoleWithPor = await this.prisma.role.update({
      where: { id },
      data: dataToUpdate,
      include: {
        permissions: { include: { permission: true } }
      }
    })
    const updatedRole = this.mapToRoleType(updatedRoleWithPor)
    if (updatedRole) {
      await this.invalidateRoleCache(updatedRole)
    }
    return updatedRole
  }

  async deleteById(id: number): Promise<PrismaRole> {
    const roleToDelete = await this.findById(id)
    const deletedRole = await this.prisma.role.delete({
      where: { id }
    })
    if (deletedRole) {
      await this.invalidateRoleCache(roleToDelete)
    }
    return deletedRole
  }
}
