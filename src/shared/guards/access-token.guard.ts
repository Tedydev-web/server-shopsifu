import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, ForbiddenException } from '@nestjs/common'
import { REQUEST_ROLE_PERMISSIONS, REQUEST_USER_KEY } from 'src/shared/constants/auth.constant'
import { HTTPMethod } from 'src/shared/constants/role.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { TokenService } from 'src/shared/services/token.service'
import { CookieService } from 'src/shared/services/cookie.service'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(
    private readonly tokenService: TokenService,
    private readonly prismaService: PrismaService,
    private readonly cookieService: CookieService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()

    // Extract và validate token từ cookies
    const decodedAccessToken = await this.extractAndValidateToken(request)

    // Check user permission
    await this.validateUserPermission(decodedAccessToken, request)
    return true
  }

  private async extractAndValidateToken(request: any): Promise<AccessTokenPayload> {
    const accessToken = this.extractAccessTokenFromCookie(request)
    if (!accessToken) {
      throw new UnauthorizedException('global.global.error.MISSING_ACCESS_TOKEN')
    }

    try {
      const decodedAccessToken = await this.tokenService.verifyAccessToken(accessToken)
      request[REQUEST_USER_KEY] = decodedAccessToken
      return decodedAccessToken
    } catch (error) {
      throw new UnauthorizedException('global.global.error.INVALID_ACCESS_TOKEN')
    }
  }

  private extractAccessTokenFromCookie(request: any): string | null {
    // Ưu tiên đọc từ cookies trước
    const cookieToken = this.cookieService.getAccessTokenFromCookie(request)
    if (cookieToken) {
      return cookieToken
    }

    // Fallback: đọc từ Authorization header (để backward compatibility)
    const headerToken = request.headers.authorization?.split(' ')[1]
    return headerToken || null
  }

  private async validateUserPermission(decodedAccessToken: AccessTokenPayload, request: any): Promise<void> {
    const roleId: number = decodedAccessToken.roleId
    const path: string = request.route.path
    const method = request.method as keyof typeof HTTPMethod

    const role = await this.prismaService.role
      .findUniqueOrThrow({
        where: {
          id: roleId,
          deletedAt: null,
          isActive: true
        },
        include: {
          permissions: {
            where: {
              deletedAt: null,
              path,
              method
            }
          }
        }
      })
      .catch(() => {
        throw new ForbiddenException()
      })

    const canAccess = role.permissions.length > 0
    if (!canAccess) {
      throw new ForbiddenException()
    }

    request[REQUEST_ROLE_PERMISSIONS] = role
  }
}
