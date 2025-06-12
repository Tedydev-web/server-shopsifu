import { Injectable, Logger } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { UserWithProfileAndRole } from 'src/routes/user/user.repository'
import { ALL_ROLES_CACHE_TTL, ROLE_CACHE_TTL } from 'src/shared/providers/redis/redis.constants'
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { PrismaService } from 'src/shared/providers/prisma/prisma.service'
import { Role } from './role.model'

type RoleWithPermissions = Prisma.RoleGetPayload<{
  include: { permissions: { include: { permission: true } } }
}>

export type CreateRoleData = {
  name: string
  description?: string | null
  isSystemRole?: boolean
  isSuperAdmin?: boolean
  permissionIds?: number[]
}

export type UpdateRoleData = Partial<CreateRoleData>

@Injectable()
export class RoleRepository {
  private readonly logger = new Logger(RoleRepository.name)
  constructor(
    private readonly prisma: PrismaService,
    private readonly redisService: RedisService
  ) {}

  private mapUserWithPermissions(
    userWithRole:
      | (Prisma.UserGetPayload<{
          include: {
            userProfile: true
            role: { include: { permissions: { include: { permission: true } } } }
          }
        }> & { role: { permissions: any } })
      | null
  ): UserWithProfileAndRole | null {
    if (!userWithRole) {
      return null
    }
    const {
      role: { permissions, ...restRole },
      ...restUser
    } = userWithRole

    return {
      ...restUser,
      role: {
        ...restRole,
        permissions: permissions.map((p: any) => p.permission)
      }
    }
  }

  private mapToRole(roleWithPermissions: RoleWithPermissions | null): Role | null {
    if (!roleWithPermissions) {
      return null
    }
    const { permissions, ...restOfRole } = roleWithPermissions
    return {
      ...restOfRole,
      permissions: permissions?.map((p) => p.permission) || []
    }
  }

  private async invalidateRoleCache(role?: Role | null): Promise<void> {
    const keysToDel: string[] = [RedisKeyManager.getAllRolesCacheKey()]
    if (role) {
      keysToDel.push(RedisKeyManager.getRoleCacheKey(role.id))
      keysToDel.push(RedisKeyManager.getRoleByNameCacheKey(role.name))
    }
    if (keysToDel.length > 0) {
      await this.redisService.del(keysToDel)
      this.logger.debug(`Invalidated role cache for keys: ${keysToDel.join(', ')}`)
    }
  }

  async create(createRoleData: CreateRoleData, createdById?: number): Promise<Role> {
    const { name, description, isSystemRole, isSuperAdmin, permissionIds } = createRoleData
    const createdRoleWithPermissions = await this.prisma.role.create({
      data: {
        name,
        description,
        isSystemRole: isSystemRole ?? false,
        isSuperAdmin: isSuperAdmin ?? false,
        createdBy: createdById ? { connect: { id: createdById } } : undefined,
        permissions:
          permissionIds && permissionIds.length > 0
            ? {
                create: permissionIds.map((pid) => ({
                  permission: { connect: { id: pid } },
                  assignedBy: createdById ? { connect: { id: createdById } } : undefined
                }))
              }
            : undefined
      },
      include: {
        permissions: {
          include: {
            permission: true
          }
        }
      }
    })

    const role = this.mapToRole(createdRoleWithPermissions)
    await this.invalidateRoleCache()
    return role
  }

  async update(id: number, updateRoleData: UpdateRoleData, updatedById?: number): Promise<Role> {
    const { permissionIds, ...restData } = updateRoleData

    const roleData: Prisma.RoleUpdateInput = {
      ...restData,
      updatedBy: updatedById ? { connect: { id: updatedById } } : undefined
    }

    if (permissionIds !== undefined) {
      // Transaction to ensure atomicity
      const [, updatedRoleWithPermissions] = await this.prisma.$transaction([
        this.prisma.rolePermission.deleteMany({ where: { roleId: id } }),
        this.prisma.role.update({
          where: { id },
          data: {
            ...roleData,
            permissions: {
              create: permissionIds.map((pid) => ({
                permission: { connect: { id: pid } },
                assignedBy: updatedById ? { connect: { id: updatedById } } : undefined
              }))
            }
          },
          include: {
            permissions: {
              include: {
                permission: true
              }
            }
          }
        })
      ])
      const role = this.mapToRole(updatedRoleWithPermissions)
      await this.invalidateRoleCache(role)
      return role
    } else {
      const updatedRoleWithPermissions = await this.prisma.role.update({
        where: { id },
        data: roleData,
        include: {
          permissions: {
            include: {
              permission: true
            }
          }
        }
      })
      const role = this.mapToRole(updatedRoleWithPermissions)
      await this.invalidateRoleCache(role)
      return role
    }
  }

  async findAll(): Promise<Role[]> {
    const cacheKey = RedisKeyManager.getAllRolesCacheKey()
    const cachedRoles = await this.redisService.getJson<Role[]>(cacheKey)
    if (cachedRoles) {
      this.logger.debug('findAll roles from cache')
      return cachedRoles
    }

    const rolesWithPermissions = await this.prisma.role.findMany({
      include: {
        permissions: {
          include: {
            permission: true
          }
        }
      }
    })
    const roles = rolesWithPermissions.map((r) => this.mapToRole(r))
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

    const roleWithPermissions = await this.prisma.role.findUnique({
      where: { id },
      include: {
        permissions: {
          include: {
            permission: true
          }
        }
      }
    })
    const role = this.mapToRole(roleWithPermissions)
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

    const roleWithPermissions = await this.prisma.role.findUnique({
      where: { name },
      include: {
        permissions: {
          include: {
            permission: true
          }
        }
      }
    })

    const role = this.mapToRole(roleWithPermissions)
    if (role) {
      await this.redisService.setJson(cacheKey, role, ROLE_CACHE_TTL)
      await this.redisService.setJson(RedisKeyManager.getRoleCacheKey(role.id), role, ROLE_CACHE_TTL)
    }
    return role
  }

  async deleteById(id: number): Promise<Role> {
    const roleToDelete = await this.prisma.role.findUnique({
      where: { id },
      include: {
        permissions: {
          include: {
            permission: true
          }
        }
      }
    })

    if (!roleToDelete) {
      throw new Error(`Role with ID ${id} not found`)
    }

    const deletedRole = await this.prisma.role.delete({ where: { id } })

    await this.invalidateRoleCache(this.mapToRole(roleToDelete as any))

    return deletedRole
  }

  async getUserWithRoleAndPermissions(userId: number): Promise<UserWithProfileAndRole | null> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        userProfile: true,
        role: {
          include: {
            permissions: {
              include: {
                permission: true
              }
            }
          }
        }
      }
    })
    return this.mapUserWithPermissions(user)
  }
}
