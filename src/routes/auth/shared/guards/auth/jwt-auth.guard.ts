import {
  Injectable,
  CanActivate,
  ExecutionContext,
  Logger,
  Inject,
  forwardRef,
  UnauthorizedException
} from '@nestjs/common'
import { REQUEST_USER_KEY } from 'src/routes/auth/shared/constants/auth.constants'
import { TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { ITokenService } from 'src/routes/auth/shared/auth.types'
import { AuthError } from 'src/routes/auth/auth.error'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { SessionsService } from 'src/routes/auth/modules/sessions/sessions.service'

@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name)

  constructor(
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    @Inject(forwardRef(() => SessionsService)) private readonly sessionService: SessionsService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()

    try {
      const token = this.tokenService.extractTokenFromRequest(request)

      if (!token) {
        this.logger.debug('JWT Auth: Access token is missing')
        throw AuthError.MissingAccessToken()
      }

      const payload = await this.tokenService.verifyAccessToken(token)

      if (!payload || !payload.sessionId) {
        this.logger.warn('JWT Auth: Session ID missing in token payload')
        throw AuthError.MissingSessionIdInToken()
      }

      if (await this.sessionService.isSessionInvalidated(payload.sessionId)) {
        this.logger.debug(`JWT Auth: Session ${payload.sessionId} has been invalidated. Access denied.`)
        throw AuthError.SessionRevoked()
      }

      request[REQUEST_USER_KEY] = payload

      return true
    } catch (error) {
      this.logger.error(`JWT authentication failed: ${error.message}`, error.stack)

      if (
        error instanceof ApiException &&
        (error.errorCode === 'SESSION_REVOKED' ||
          error.errorCode === 'MISSING_SESSION_ID_IN_TOKEN' ||
          error.errorCode === 'MISSING_ACCESS_TOKEN')
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

      throw error
    }
  }
}
