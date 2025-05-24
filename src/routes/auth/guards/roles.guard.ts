import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { ROLES_KEY } from '../decorators/roles.decorator'
import { RoleNameValue } from '../constants/role.constant'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth.constant'

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<RoleNameValue[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass()
    ])
    if (!requiredRoles) {
      return true
    }
    const request = context.switchToHttp().getRequest()
    const user = request[REQUEST_USER_KEY] as AccessTokenPayload | undefined

    if (!user || !user.roleName) {
      throw new ForbiddenException('Error.Auth.Access.Denied')
    }

    const userRole = user.roleName as RoleNameValue
    return requiredRoles.some((role) => userRole === role)
  }
}
