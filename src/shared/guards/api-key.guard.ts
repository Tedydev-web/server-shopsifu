import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { REQUEST_USER_KEY } from 'src/routes/auth/auth.constants'

@Injectable()
export class ApiKeyGuard implements CanActivate {
  private readonly logger = new Logger(ApiKeyGuard.name)
  private readonly apiKey: string

  constructor(private readonly configService: ConfigService) {
    this.apiKey = this.configService.get<string>('SECRET_API_KEY', '') // Default to empty if not found
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest()
    const providedApiKey = request.headers['x-api-key'] || request.query.apiKey

    // Case 1: Server is not configured with an API key (this.apiKey is empty).
    if (!this.apiKey) {
      throw new UnauthorizedException('API key authentication failed: Service configuration error.')
    }

    // Case 2: Client did not provide an API key.
    if (!providedApiKey) {
      throw new UnauthorizedException('API key is missing.')
    }

    // Case 3: Client provided an incorrect API key.
    if (providedApiKey !== this.apiKey) {
      throw new UnauthorizedException('Invalid API key.')
    }

    // All checks passed.
    request[REQUEST_USER_KEY] = {
      isApiKey: true,
      apiKeyType: 'system' // Or a more specific identifier if available
    }
    return true
  }
}
