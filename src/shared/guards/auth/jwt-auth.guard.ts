import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Logger,
  Inject,
  forwardRef
} from '@nestjs/common'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth.constants'
import { TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { ITokenService } from 'src/shared/types/auth.types'
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

      // Nếu lỗi đã là một trong các AuthError cụ thể của chúng ta, ném lại nó
      if (
        error instanceof ApiException &&
        (error.errorCode === 'SESSION_REVOKED' ||
          error.errorCode === 'MISSING_SESSION_ID_IN_TOKEN' ||
          error.errorCode === 'MISSING_ACCESS_TOKEN')
      ) {
        throw error
      }

      // Kiểm tra các lỗi từ jwtService.verifyAsync (thường được bao bởi UnauthorizedException)
      if (error instanceof UnauthorizedException) {
        // Kiểm tra cụ thể hơn về nguyên nhân lỗi từ verifyAccessToken
        // Ví dụ: lỗi hết hạn token thường có message 'jwt expired' hoặc một inner error type
        if (error.message?.toLowerCase().includes('jwt expired')) {
          this.logger.debug('JWT Auth: Access token expired.')
          throw AuthError.AccessTokenExpired()
        } else if (error.message?.toLowerCase().includes('invalid signature')) {
          this.logger.warn('JWT Auth: Invalid token signature.')
          throw AuthError.InvalidAccessToken() // Hoặc một lỗi cụ thể hơn như TokenSignatureInvalid
        } else if (error.message?.toLowerCase().includes('jwt malformed')) {
          this.logger.warn('JWT Auth: Token malformed.')
          throw AuthError.InvalidAccessToken() // Hoặc một lỗi cụ thể hơn như TokenMalformed
        }
        // Các trường hợp UnauthorizedException khác không rõ nguyên nhân cụ thể từ token
        this.logger.warn(`JWT Auth: Unauthorized - ${error.message}`)
        throw AuthError.InvalidAccessToken() // Fallback cho các lỗi token không xác định rõ
      }

      // Nếu là lỗi khác không mong muốn, ném lại lỗi gốc hoặc một lỗi server chung
      this.logger.error('JWT Auth: Unhandled error during token validation.', error.stack)
      throw error // Hoặc AuthError.InternalServerError(error.message)
    }
  }
}
