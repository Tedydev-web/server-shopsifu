import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common'
import { TokenService } from 'src/routes/auth/shared/token/token.service'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth.constant'

@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name)

  constructor(private readonly tokenService: TokenService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()
    
    try {
      const token = this.tokenService.extractTokenFromRequest(request)
      
      if (!token) {
        throw new UnauthorizedException('Access token is missing')
      }
      
      const payload = await this.tokenService.verifyAccessToken(token)
      
      // Kiểm tra xem session có bị vô hiệu hóa không
      if (await this.tokenService.isSessionInvalidated(payload.sessionId)) {
        throw new UnauthorizedException('Session has been invalidated')
      }
      
      // Thiết lập thông tin user vào request
      request[REQUEST_USER_KEY] = payload
      
      return true
    } catch (error) {
      this.logger.error(`JWT authentication failed: ${error.message}`)
      throw new UnauthorizedException('Invalid or expired access token')
    }
  }
} 