import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth/auth.constants'

@Injectable()
export class ApiKeyGuard implements CanActivate {
  private readonly logger = new Logger(ApiKeyGuard.name)
  private readonly apiKey: string

  constructor(private readonly configService: ConfigService) {
    this.apiKey = this.configService.get<string>('SECRET_API_KEY', '')
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest()

    try {
      const apiKey = request.headers['x-api-key'] || request.query.apiKey

      if (!apiKey) {
        throw new UnauthorizedException('API key is missing')
      }

      if (apiKey !== this.apiKey) {
        throw new UnauthorizedException('Invalid API key')
      }

      request[REQUEST_USER_KEY] = {
        isApiKey: true,
        apiKeyType: 'system'
      }

      return true
    } catch (error) {
      this.logger.error(`API key authentication failed: ${error.message}`)
      throw new UnauthorizedException('API key authentication failed')
    }
  }
}
