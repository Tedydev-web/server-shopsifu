import { Injectable, CanActivate, ExecutionContext, HttpException, UnauthorizedException } from '@nestjs/common'
import { Request } from 'express'
import { REQUEST_USER_KEY, REQUEST_ROLE_PERMISSIONS } from 'src/shared/constants/auth.constant'
import { CookieNames } from 'src/shared/constants/cookie.constant'
import { TokenService } from 'src/shared/services/auth/token.service'
import { SessionService } from '../services/auth/session.service'
import { AuthError } from 'src/routes/auth/auth.error'
import { SharedRoleRepository } from 'src/shared/repositories/shared-role.repo'
import { I18nService } from 'nestjs-i18n'

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(
    private readonly tokenService: TokenService,
    private readonly sessionService: SessionService,
    private readonly sharedRoleRepository: SharedRoleRepository,
    private readonly i18n: I18nService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>()
    const accessToken = this.extractToken(request)

    if (!accessToken) {
      throw new UnauthorizedException(this.i18n.t('auth.error.ACCESS_TOKEN_REQUIRED'))
    }

    try {
      // 1. Verify access token
      const payload = await this.tokenService.verifyAccessToken(accessToken)

      // 2. Check if token is blacklisted or session is invalid
      const [isBlacklisted, session] = await Promise.all([
        this.sessionService.isBlacklisted(payload.jti),
        this.sessionService.getSession(payload.sessionId),
      ])

      if (isBlacklisted) {
        throw AuthError.TokenBlacklisted
      }

      if (!session) {
        throw AuthError.SessionNotFound
      }

      // 3. Lấy role (kèm permissions) từ DB
      const role = await this.sharedRoleRepository.getRoleByIdIncludePermissions(payload.roleId)
      if (!role) {
        throw AuthError.RoleNotFound
      }

      // 4. Kiểm tra quyền truy cập route/method hiện tại
      const path = request.route?.path || request.path
      const method = request.method
      const canAccess = role.permissions.some(
        (permission) => permission.path === path && permission.method === method && !permission.deletedAt,
      )
      if (!canAccess) {
        throw AuthError.InsufficientPermissions
      }

      // 5. Store user info và role permissions vào request
      request[REQUEST_USER_KEY] = {
        userId: payload.userId,
        sessionId: payload.sessionId,
        roleId: payload.roleId,
        roleName: payload.roleName,
        deviceId: session.deviceId,
        jti: payload.jti,
      }
      request[REQUEST_ROLE_PERMISSIONS] = role

      return true
    } catch (error) {
      // Ensure only our standardized errors are thrown
      if (error instanceof HttpException) {
        throw error
      }
      // Fallback for unexpected JWT errors (e.g., malformed token)
      throw new UnauthorizedException(this.i18n.t('auth.error.INVALID_ACCESS_TOKEN'))
    }
  }

  private extractToken(request: Request): string | undefined {
    // 1. Priority: Get from cookie
    const fromCookie = request.cookies[CookieNames.ACCESS_TOKEN]
    if (fromCookie) {
      return fromCookie
    }

    // 2. Fallback: Get from header
    const [type, token] = request.headers.authorization?.split(' ') ?? []
    return type === 'Bearer' ? token : undefined
  }
}
