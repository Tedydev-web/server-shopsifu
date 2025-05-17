import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth.constant'
import { TokenService } from 'src/shared/services/token.service'
import { Request } from 'express'

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(private readonly tokenService: TokenService) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>()
    
    // Lấy token từ cookie hoặc authorization header
    const token = this.tokenService.extractTokenFromRequest(request)
    
    if (!token) {
      throw new UnauthorizedException('Error.MissingAccessToken')
    }
    
    try {
      const decodedAccessToken = await this.tokenService.verifyAccessToken(token)
      request[REQUEST_USER_KEY] = decodedAccessToken
      return true
    } catch {
      throw new UnauthorizedException('Error.InvalidOrExpiredAccessToken')
    }
  }
}
