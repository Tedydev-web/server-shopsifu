import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth.constants'

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
      // Lấy API key từ header X-API-KEY hoặc query param
      const apiKey = request.headers['x-api-key'] || request.query.apiKey

      if (!apiKey) {
        throw new UnauthorizedException('API key is missing')
      }

      // Kiểm tra API key
      if (apiKey !== this.apiKey) {
        throw new UnauthorizedException('Invalid API key')
      }

      // Thiết lập thông tin vào request
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
