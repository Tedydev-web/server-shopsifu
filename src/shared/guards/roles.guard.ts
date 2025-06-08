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
    const request = context.switchToHttp().getRequest<Request & { user: AccessTokenPayload }>()
    const { roleName } = request.user

    if (!roleName) {
      return false
    }

    // Kiểm tra nếu có role "admin" thì luôn được phép
    if (roleName === 'admin') {
      return true
    }

    // Ngược lại, kiểm tra xem role của user có trong các role được yêu cầu không
    return requiredRoles.some((role) => roleName === role)
  }
}
