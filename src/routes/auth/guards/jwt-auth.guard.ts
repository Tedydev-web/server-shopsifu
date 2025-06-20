import {
  Injectable,
  CanActivate,
  ExecutionContext,
  Logger,
  Inject,
  forwardRef,
  UnauthorizedException,
  ForbiddenException
} from '@nestjs/common'
import { ClsService } from 'nestjs-cls'
import { TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { ITokenService, AccessTokenPayload } from 'src/routes/auth/auth.types'
import { AuthError } from 'src/routes/auth/auth.error'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { SessionsService } from 'src/routes/auth/services/session.service'
import { UserRepository } from 'src/routes/user/user.repository'
import { ActiveUserData } from 'src/shared/types/active-user.type'
import { UserStatus } from '@prisma/client'

@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name)

  constructor(
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    @Inject(forwardRef(() => SessionsService)) private readonly sessionService: SessionsService,
    private readonly userRepository: UserRepository,
    private readonly cls: ClsService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()

    try {
      const token = this.tokenService.extractTokenFromRequest(request)

      if (!token) {
        throw AuthError.MissingAccessToken()
      }

      const payload: AccessTokenPayload = await this.tokenService.verifyAccessToken(token)

      if (!payload || !payload.sessionId) {
        throw AuthError.MissingSessionIdInToken()
      }

      if (await this.sessionService.isSessionInvalidated(payload.sessionId)) {
        throw AuthError.SessionRevoked()
      }

      const user = await this.userRepository.findByIdWithDetails(payload.userId)

      if (!user) {
        throw new ForbiddenException('User belonging to this token no longer exists.')
      }

      if (user.status !== UserStatus.ACTIVE) {
        throw AuthError.Unauthorized('User is not active')
      }

      const activeUser: ActiveUserData = {
        ...user,
        sessionId: payload.sessionId,
        deviceId: payload.deviceId,
        isDeviceTrustedInSession: payload.isDeviceTrustedInSession
      }

      // Store the user object in the CLS context
      this.cls.set('user', activeUser)

      // Also attach to request for compatibility, though CLS is preferred
      request.user = activeUser

      return true
    } catch (error) {
      if (
        error instanceof ApiException &&
        (error.code === 'SESSION_REVOKED' ||
          error.code === 'MISSING_SESSION_ID_IN_TOKEN' ||
          error.code === 'MISSING_ACCESS_TOKEN')
      ) {
        throw error
      }

      if (error instanceof UnauthorizedException) {
        if (error.message?.toLowerCase().includes('jwt expired')) {
          throw AuthError.AccessTokenExpired()
        } else if (error.message?.toLowerCase().includes('invalid signature')) {
          throw AuthError.InvalidAccessToken()
        } else if (error.message?.toLowerCase().includes('jwt malformed')) {
          throw AuthError.InvalidAccessToken()
        }
        throw AuthError.InvalidAccessToken()
      }

      throw AuthError.Unauthorized() // Use a generic unauthorized error
    }
  }
}
