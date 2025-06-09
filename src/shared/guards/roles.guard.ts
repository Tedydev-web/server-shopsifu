import { CanActivate, ExecutionContext, Injectable, Logger } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Observable } from 'rxjs'
import { ROLES_KEY } from 'src/shared/decorators/auth.decorator'
import { Request } from 'express'
import { AccessTokenPayload } from 'src/shared/types/auth.types'

@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger(RolesGuard.name)

  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass()
    ])

    if (!requiredRoles) {
      return true
    }
    const request = context.switchToHttp().getRequest<Request & { user?: AccessTokenPayload }>()

    // If the user object or roleName is not present on the request (e.g., auth guard failed or didn't attach user),
    // then access should be denied if roles are required.
    if (!request.user || !request.user.roleName) {
      this.logger.warn('User object or roleName missing in request. Denying access for role-protected route.')
      return false
    }
    const { roleName } = request.user

    // Note: The previous `if (!roleName)` check is now covered by `!request.user.roleName`
    // if (!roleName) { // This check is redundant if the above is implemented
    //   return false
    // }

    // Kiểm tra nếu có role "admin" thì luôn được phép
    if (roleName === 'admin') {
      return true
    }

    // Ngược lại, kiểm tra xem role của user có trong các role được yêu cầu không
    return requiredRoles.some((role) => roleName === role)
  }
}
