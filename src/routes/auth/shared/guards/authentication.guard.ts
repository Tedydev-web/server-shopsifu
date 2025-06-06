import { CanActivate, ExecutionContext, Injectable, Logger } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { AuthType } from 'src/routes/auth/shared/constants/auth.constants'
import { AUTH_TYPE_KEY, IS_PUBLIC_KEY } from 'src/routes/auth/shared/decorators/auth.decorator'
import { Observable } from 'rxjs'
import { ApiKeyGuard } from './auth/api-key.guard'
import { JwtAuthGuard } from './auth/jwt-auth.guard'
import { BasicAuthGuard } from './auth/basic-auth.guard'

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

    const authTypes = this.reflector.getAllAndOverride<AuthType[]>('auth_type', [
      context.getHandler(),
      context.getClass()
    ])

    // Nếu không có decorator @Auth, sử dụng JWT mặc định
    const selectedAuthType = authTypes?.[0] || this.defaultAuthType

    // Lấy guard tương ứng với auth type
    const guard = this.authTypeGuardMap[selectedAuthType]

    if (!guard) {
      throw new Error(`Unsupported authentication type: ${selectedAuthType}`)
    }

    return guard.canActivate(context)
  }
}
