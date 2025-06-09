import { CanActivate, ExecutionContext, Injectable, InternalServerErrorException } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { AUTH_TYPE_KEY, IS_PUBLIC_KEY } from 'src/shared/decorators/auth.decorator'
import { AuthType } from 'src/shared/constants/auth/auth.constants'

import { Observable } from 'rxjs'
import { ApiKeyGuard } from './api-key.guard'
import { JwtAuthGuard } from './jwt-auth.guard'
import { BasicAuthGuard } from './basic-auth.guard'

@Injectable()
export class AuthenticationGuard implements CanActivate {
  private readonly defaultAuthType = AuthType.JWT
  private readonly authTypeGuardMap: Record<AuthType, CanActivate> = {
    [AuthType.JWT]: this.jwtAuthGuard,
    [AuthType.Bearer]: this.jwtAuthGuard,
    [AuthType.ApiKey]: this.apiKeyGuard,
    [AuthType.Basic]: this.basicAuthGuard,
    [AuthType.None]: { canActivate: () => true }
  }

  constructor(
    private readonly reflector: Reflector,
    private readonly jwtAuthGuard: JwtAuthGuard,
    private readonly apiKeyGuard: ApiKeyGuard,
    private readonly basicAuthGuard: BasicAuthGuard
  ) {}

  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    // Kiểm tra xem route có được đánh dấu là public không
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass()
    ])

    // Nếu route là public, cho phép truy cập
    if (isPublic) {
      return true
    }

    // Get the authentication types specified by the @Auth() decorator.
    // If multiple auth types are provided, this guard currently only considers the first one.
    // For 'OR' logic across multiple auth types, this guard would need further enhancement.
    const authTypes = this.reflector.getAllAndOverride<AuthType[]>(AUTH_TYPE_KEY, [
      context.getHandler(),
      context.getClass()
    ])

    // Nếu không có decorator @Auth, sử dụng JWT mặc định
    const selectedAuthType = authTypes?.[0] || this.defaultAuthType

    // Lấy guard tương ứng với auth type
    const guard = this.authTypeGuardMap[selectedAuthType]

    if (!guard) {
      // This indicates a configuration error (e.g., an unsupported AuthType was used in @Auth decorator)
      throw new InternalServerErrorException(`Unsupported authentication type: ${selectedAuthType}`)
    }

    return guard.canActivate(context)
  }
}
