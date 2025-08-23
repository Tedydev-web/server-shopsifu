import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, ForbiddenException } from '@nestjs/common'
import { keyBy } from 'lodash'
import { REQUEST_ROLE_PERMISSIONS, REQUEST_USER_KEY } from 'src/shared/constants/auth.constant'
import { HTTPMethod } from 'src/shared/constants/role.constant'
import { RolePermissionsType } from 'src/shared/models/shared-role.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { TokenService } from 'src/shared/services/token.service'
import { RedisService } from 'src/shared/services/redis.service'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

type Permission = RolePermissionsType['permissions'][number]
type CachedRole = RolePermissionsType & {
  permissions: Record<string, Permission>
}

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(
    private readonly tokenService: TokenService,
    private readonly prismaService: PrismaService,
    private readonly redisService: RedisService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()

    // Extract và validate token
    const decodedAccessToken = await this.extractAndValidateToken(request)

    // Check user permission
    await this.validateUserPermission(decodedAccessToken, request)

    return true
  }

  private async extractAndValidateToken(request: any): Promise<AccessTokenPayload> {
    const accessToken = this.extractAccessTokenFromHeader(request)

    try {
      const decodedAccessToken = await this.tokenService.verifyAccessToken(accessToken)
      request[REQUEST_USER_KEY] = decodedAccessToken
      return decodedAccessToken
    } catch (error) {
      throw new UnauthorizedException('Error.InvalidAccessToken')
    }
  }

  private extractAccessTokenFromHeader(request: any): string {
    const accessToken = request.cookies?.['access_token']
    if (!accessToken) {
      throw new UnauthorizedException('Error.MissingAccessToken')
    }
    return accessToken
  }

  private async validateUserPermission(decodedAccessToken: AccessTokenPayload, request: any): Promise<void> {
    const { roleId } = decodedAccessToken
    const path = request.route?.path || request.url
    const method = request.method as keyof typeof HTTPMethod
    const cacheKey = `role:${roleId}`
    // 1. Thử lấy từ cache
    let cachedRole = await this.redisService.get<CachedRole>(cacheKey)
    // 2. Nếu không có trong cache, thì truy vấn từ cơ sở dữ liệu
    if (!cachedRole) {
      try {
        const role = await this.prismaService.role.findUniqueOrThrow({
          where: {
            id: roleId,
            deletedAt: null,
            isActive: true
          },
          include: {
            permissions: {
              where: {
                deletedAt: null
              }
            }
          }
        })

        const permissionObject = keyBy(
          role.permissions,
          (permission) => `${permission.path}:${permission.method}`
        ) as CachedRole['permissions']

        cachedRole = { ...role, permissions: permissionObject }
        await this.redisService.set(cacheKey, cachedRole, 3600) // Cache for 1 hour
        request[REQUEST_ROLE_PERMISSIONS] = role
      } catch {
        throw new ForbiddenException('Error.RoleNotFound')
      }
    }

    // 3. Kiểm tra quyền truy cập
    if (!cachedRole) {
      throw new ForbiddenException('Error.InvalidRole')
    }

    const canAccess: Permission | undefined = cachedRole.permissions[`${path}:${method}`]
    if (!canAccess) {
      throw new ForbiddenException('Error.InsufficientPermissions')
    }
  }
}
