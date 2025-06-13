import { Injectable, CanActivate, ExecutionContext, Logger } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { AUTH_TYPE_KEY, IS_PUBLIC_KEY } from 'src/shared/decorators/auth.decorator'
import { AuthType } from 'src/routes/auth/auth.constants'
import { Observable } from 'rxjs'
import { JwtAuthGuard } from './jwt-auth.guard'
import { ApiKeyGuard } from 'src/shared/guards/api-key.guard'
import { BasicAuthGuard } from './basic-auth.guard'

@Injectable()
export class AuthenticationGuard implements CanActivate {
  private readonly logger = new Logger(AuthenticationGuard.name)
  private readonly defaultAuthType = AuthType.JWT
  private readonly authTypeGuardMap: Record<AuthType, CanActivate | undefined>

  constructor(
    private readonly reflector: Reflector,
    private readonly jwtAuthGuard: JwtAuthGuard,
    private readonly apiKeyGuard: ApiKeyGuard,
    private readonly basicAuthGuard: BasicAuthGuard
  ) {
    this.authTypeGuardMap = {
      [AuthType.JWT]: this.jwtAuthGuard,
      [AuthType.ApiKey]: this.apiKeyGuard,
      [AuthType.Basic]: this.basicAuthGuard,
      [AuthType.Bearer]: this.jwtAuthGuard,
      [AuthType.None]: undefined // No guard for 'None'
    }
  }

  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass()
    ])

    if (isPublic) {
      return true
    }

    const authTypes =
      this.reflector.getAllAndOverride<AuthType[]>(AUTH_TYPE_KEY, [context.getHandler(), context.getClass()]) ?? []

    if (authTypes.length === 0) {
      authTypes.push(this.defaultAuthType)
    }

    for (const type of authTypes) {
      const guard = this.authTypeGuardMap[type]
      if (guard) {
        return guard.canActivate(context)
      }
    }

    return true
  }
}
