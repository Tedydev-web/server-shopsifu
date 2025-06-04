import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger, Inject } from '@nestjs/common'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth.constants'
import { TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { ITokenService } from 'src/shared/types/auth.types'
import { AuthError } from 'src/routes/auth/auth.error'

@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name)

  constructor(@Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()

    try {
      const token = this.tokenService.extractTokenFromRequest(request)

      if (!token) {
        this.logger.debug('JWT Auth: Access token is missing')
        throw AuthError.MissingAccessToken()
      }

      const payload = await this.tokenService.verifyAccessToken(token)

      // Kiểm tra sessionId tồn tại trong payload
      if (!payload || !payload.sessionId) {
        this.logger.warn('JWT Auth: Session ID missing in token payload')
        throw AuthError.MissingSessionIdInToken()
      }

      // Kiểm tra xem session có bị vô hiệu hóa không
      if (await this.tokenService.isSessionInvalidated(payload.sessionId)) {
        this.logger.debug(`JWT Auth: Session ${payload.sessionId} has been invalidated. Access denied.`)
        throw AuthError.SessionNotFound()
      }

      // Thiết lập thông tin user vào request
      request[REQUEST_USER_KEY] = payload

      return true
    } catch (error) {
      this.logger.error(`JWT authentication failed: ${error.message}`, error.stack)
      if (error instanceof UnauthorizedException && error.getStatus() === 401) {
        // Nếu lỗi đã là dạng AuthError (UNAUTHORIZED), ném lại chính nó
        // Hoặc nếu là lỗi JWT hết hạn cụ thể từ verifyAccessToken (thường là UnauthorizedException)
        throw AuthError.InvalidAccessToken()
      }
      // Nếu là lỗi khác không mong muốn, có thể xem xét ném lỗi chung hơn hoặc xử lý cụ thể
      throw error
    }
  }
}
