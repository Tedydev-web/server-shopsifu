import { Injectable, CanActivate, ExecutionContext, Logger, UnauthorizedException } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Request } from 'express'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth.constant'
import { PrismaService } from '../services/prisma.service'
import { RedisService } from '../providers/redis/redis.service'
import { RedisKeyManager } from '../providers/redis/redis-key.manager'
import { I18nService } from 'nestjs-i18n'
import {
  InsufficientPermissionsException,
  NotFoundRecordException,
  SessionNotFoundException,
  UserNotActiveException
} from '../error'

export interface RequiredPermission {
  resource: string
  action: string
}

export const PERMISSIONS_KEY = 'permissions'

@Injectable()
export class PermissionGuard implements CanActivate {
  private readonly CACHE_TTL = 5 * 60 // 5 minutes
  private readonly DEVICE_CACHE_TTL = 10 * 60 // 10 minutes
  private readonly logger = new Logger(PermissionGuard.name)

  // Mapping từ action sang HTTP method
  private readonly actionToMethodMap: Record<string, string> = {
    read: 'GET',
    create: 'POST',
    update: 'PUT',
    delete: 'DELETE',
    manage: 'GET' // manage có thể truy cập tất cả methods
  }

  constructor(
    private readonly reflector: Reflector,
    private readonly prismaService: PrismaService,
    private readonly redisService: RedisService,
    private readonly i18n: I18nService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.get<RequiredPermission[]>(PERMISSIONS_KEY, context.getHandler())

    // If no permissions required, allow access
    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true
    }

    const request = context.switchToHttp().getRequest<Request>()
    const user = request[REQUEST_USER_KEY]

    if (!user) {
      this.logDenied(request, 'NO_USER_IN_REQUEST', null)
      throw new UnauthorizedException(this.i18n.t('auth.error.ACCESS_TOKEN_REQUIRED'))
    }

    // 1. Kiểm tra trạng thái user và role (có thể cache nếu cần)
    const dbUser = await this.prismaService.user.findUnique({
      where: { id: user.userId },
      select: { status: true, role: { select: { isActive: true } } }
    })
    if (!dbUser) {
      this.logDenied(request, 'USER_NOT_FOUND', user)
      throw NotFoundRecordException
    }
    if (!dbUser.role || !dbUser.role.isActive) {
      this.logDenied(request, 'ROLE_NOT_ACTIVE', user)
      throw UserNotActiveException
    }
    if (dbUser.status !== 'ACTIVE') {
      this.logDenied(request, `USER_STATUS_${dbUser.status}`, user)
      throw UserNotActiveException
    }

    // 2. Validate device (with caching)
    try {
      await this.validateDevice(user.deviceId)
    } catch (err) {
      this.logDenied(request, 'DEVICE_INVALID', user, err)
      throw err
    }

    // 3. Get user permissions (with caching)
    let userPermissions: Array<{ path: string; method: string }>
    try {
      userPermissions = await this.getUserPermissions(user.roleId)
    } catch (err) {
      this.logDenied(request, 'ROLE_OR_PERMISSION_INVALID', user, err)
      throw err
    }

    // 4. Check if user has required permissions
    this.logger.debug(`User permissions: ${JSON.stringify(userPermissions)}`)
    this.logger.debug(`Required permissions: ${JSON.stringify(requiredPermissions)}`)

    const hasPermission = await this.checkPermissions(userPermissions, requiredPermissions)

    if (!hasPermission) {
      this.logDenied(request, 'INSUFFICIENT_PERMISSIONS', user)
      throw InsufficientPermissionsException
    }

    return true
  }

  private async validateDevice(deviceId: number): Promise<void> {
    const cacheKey = RedisKeyManager.getDeviceStatusKey(deviceId)

    // Try to get from cache first
    const cachedStatus = await this.redisService.get<{ isActive: boolean }>(cacheKey)

    if (cachedStatus) {
      if (!cachedStatus.isActive) {
        throw UserNotActiveException
      }
      return
    }

    // Query database if not in cache
    const device = await this.prismaService.device.findUnique({
      where: { id: deviceId },
      select: { isActive: true }
    })

    if (!device) {
      throw SessionNotFoundException
    }

    if (!device.isActive) {
      throw UserNotActiveException
    }

    // Cache the result
    await this.redisService.set(cacheKey, { isActive: device.isActive }, this.DEVICE_CACHE_TTL)
  }

  private async getUserPermissions(roleId: number): Promise<Array<{ path: string; method: string }>> {
    const cacheKey = RedisKeyManager.getRolePermissionsKey(roleId)

    // Try to get from cache first
    const cachedPermissions = await this.redisService.get<Array<{ path: string; method: string }>>(cacheKey)

    if (cachedPermissions) {
      return cachedPermissions
    }

    // Query database if not in cache
    const roleWithPermissions = await this.prismaService.role.findUnique({
      where: { id: roleId },
      include: {
        permissions: {
          where: { deletedAt: null },
          select: { path: true, method: true }
        }
      }
    })

    if (!roleWithPermissions) {
      throw NotFoundRecordException
    }

    const permissions = roleWithPermissions.permissions.map((p) => ({
      path: p.path,
      method: p.method
    }))

    // Cache the result
    await this.redisService.set(cacheKey, permissions, this.CACHE_TTL)

    return permissions
  }

  private async getResourcePathMapping(resource: string, method: string): Promise<string> {
    const cacheKey = RedisKeyManager.getResourcePathMappingKey(`${resource}-${method}`)

    // Try to get from cache first
    const cachedPath = await this.redisService.get<string>(cacheKey)
    if (cachedPath) {
      return cachedPath
    }

    // Query database to find the actual path for this resource and method combination
    const permission = await this.prismaService.permission.findFirst({
      where: {
        deletedAt: null,
        method: method as any,
        OR: [
          // Try exact match first
          { path: `/${resource}s` },
          { path: `/${resource}` },
          // Try with common patterns
          { path: { contains: resource, mode: 'insensitive' } }
        ]
      },
      select: { path: true },
      orderBy: [
        // Prioritize paths with parameters for non-GET methods
        method !== 'GET' ? { path: 'desc' } : { path: 'asc' }
      ]
    })

    if (!permission) {
      // Fallback to default pattern if no match found
      const defaultPath = method === 'GET' || method === 'POST' ? `/${resource}s` : `/${resource}s/:${resource}Id`

      // Cache the fallback to avoid repeated DB queries
      await this.redisService.set(cacheKey, defaultPath, this.CACHE_TTL)

      return defaultPath
    }

    // Cache the found path
    await this.redisService.set(cacheKey, permission.path, this.CACHE_TTL)

    return permission.path
  }

  private getMethodFromAction(action: string): string {
    const method = this.actionToMethodMap[action.toLowerCase()]
    if (!method) {
      this.logger.warn(`Unknown action: ${action}, defaulting to GET`)
      return 'GET'
    }
    return method
  }

  private async matchesPermission(
    userPermission: { path: string; method: string },
    requiredPermission: RequiredPermission
  ): Promise<boolean> {
    // Get the HTTP method from action first
    const requiredMethod = this.getMethodFromAction(requiredPermission.action)
    // Get the actual path from database/cache
    const permissionPath = await this.getResourcePathMapping(requiredPermission.resource, requiredMethod)

    // Debug logging
    this.logger.debug(
      `Permission check: userPermission=${JSON.stringify(userPermission)}, requiredPermission=${JSON.stringify(requiredPermission)}, permissionPath=${permissionPath}, requiredMethod=${requiredMethod}`
    )

    // Check if path and method match
    const matches = userPermission.path === permissionPath && userPermission.method === requiredMethod

    this.logger.debug(`Permission match result: ${matches}`)

    return matches
  }

  private async checkPermissions(
    userPermissions: Array<{ path: string; method: string }>,
    requiredPermissions: RequiredPermission[]
  ): Promise<boolean> {
    // Pre-load all resource mappings to avoid multiple DB queries
    const resourceMappings = new Map<string, string>()

    for (const required of requiredPermissions) {
      const requiredMethod = this.getMethodFromAction(required.action)
      const resourceKey = `${required.resource}-${requiredMethod}`
      if (!resourceMappings.has(resourceKey)) {
        const path = await this.getResourcePathMapping(required.resource, requiredMethod)
        resourceMappings.set(resourceKey, path)
      }
    }

    // Check each required permission
    for (const required of requiredPermissions) {
      const requiredMethod = this.getMethodFromAction(required.action)
      const resourceKey = `${required.resource}-${requiredMethod}`
      const permissionPath = resourceMappings.get(resourceKey)!

      const hasThisPermission = userPermissions.some(
        (permission) => permission.path === permissionPath && permission.method === requiredMethod
      )

      if (!hasThisPermission) {
        this.logger.debug(
          `Missing permission: required=${JSON.stringify(required)}, path=${permissionPath}, method=${requiredMethod}`
        )
        return false
      }
    }

    return true
  }

  private logDenied(request: Request, reason: string, user: any, error?: any) {
    const userId = user?.userId || 'unknown'
    const roleId = user?.roleId || 'unknown'
    const deviceId = user?.deviceId || 'unknown'
    let ip = request.ip
    const xff = request.headers['x-forwarded-for']
    if (Array.isArray(xff)) {
      ip = xff[0] || ip || 'unknown'
    } else if (typeof xff === 'string') {
      ip = xff.split(',')[0].trim() || ip || 'unknown'
    } else {
      ip = ip || 'unknown'
    }
    const endpoint = `${request.method} ${request.originalUrl}`
    this.logger.warn(
      `Access denied: userId=${userId}, roleId=${roleId}, deviceId=${deviceId}, ip=${ip}, endpoint=${endpoint}, reason=${reason}, error=${error?.message || ''}`
    )
  }
}
