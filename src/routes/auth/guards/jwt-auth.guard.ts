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
import { REQUEST_USER_KEY } from 'src/routes/auth/auth.constants'
import { TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { ITokenService, AccessTokenPayload } from 'src/routes/auth/auth.types'
import { AuthError } from 'src/routes/auth/auth.error'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { SessionsService } from 'src/routes/auth/services/session.service'
import { UserRepository } from 'src/routes/user/user.repository'

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
        this.logger.debug('JWT Auth: Access token is missing')
        throw AuthError.MissingAccessToken()
      }

      const payload: AccessTokenPayload = await this.tokenService.verifyAccessToken(token)

      if (!payload || !payload.sessionId) {
        this.logger.warn('JWT Auth: Session ID missing in token payload')
        throw AuthError.MissingSessionIdInToken()
      }

      if (await this.sessionService.isSessionInvalidated(payload.sessionId)) {
        this.logger.debug(`JWT Auth: Session ${payload.sessionId} has been invalidated. Access denied.`)
        throw AuthError.SessionRevoked()
      }

      const user = await this.userRepository.findByIdWithDetails(payload.userId)

      if (!user) {
        this.logger.warn(`Authenticated user with ID ${payload.userId} not found in database.`)
        throw new ForbiddenException('User belonging to this token no longer exists.')
      }

      const userWithContext = {
        ...user,
        sessionId: payload.sessionId,
        deviceId: payload.deviceId,
        isDeviceTrustedInSession: payload.isDeviceTrustedInSession
      }

      // Store the user object in the CLS context
      this.cls.set(REQUEST_USER_KEY, userWithContext)

      // Also attach to request for compatibility, though CLS is preferred
      request[REQUEST_USER_KEY] = userWithContext

      return true
    } catch (error) {
      this.logger.error(`JWT authentication failed: ${error.message}`, error.stack)

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
          this.logger.debug('JWT Auth: Access token expired.')
          throw AuthError.AccessTokenExpired()
        } else if (error.message?.toLowerCase().includes('invalid signature')) {
          this.logger.warn('JWT Auth: Invalid token signature.')
          throw AuthError.InvalidAccessToken()
        } else if (error.message?.toLowerCase().includes('jwt malformed')) {
          this.logger.warn('JWT Auth: Token malformed.')
          throw AuthError.InvalidAccessToken()
        }
        this.logger.warn(`JWT Auth: Unauthorized - ${error.message}`)
        throw AuthError.InvalidAccessToken()
      }

      // For any errors not specifically handled above, throw a generic authentication failure.
      // This ensures that we always return a well-formed ApiException.
      this.logger.error(
        `JWT Auth: Unhandled error type during authentication: ${error?.constructor?.name}`,
        error.stack
      )
      throw AuthError.Unauthorized() // Use a generic unauthorized error
    }
  }
}
