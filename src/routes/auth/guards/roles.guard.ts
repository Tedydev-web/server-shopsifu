import { Injectable, CanActivate, ExecutionContext, Logger } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Request } from 'express'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { ROLES_KEY } from '../decorators/auth.decorator'

@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger(RolesGuard.name)

  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass()
    ])

    if (!requiredRoles || requiredRoles.length === 0) {
      return true
    }

    const request = context.switchToHttp().getRequest<Request>()
    const user = request['user'] as AccessTokenPayload

    if (!user) {
      return false
    }

    return requiredRoles.some((role) => user.roleName === role)
  }
}
