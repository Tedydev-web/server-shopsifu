import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth/auth.constants'

@Injectable()
export class ApiKeyGuard implements CanActivate {
  private readonly logger = new Logger(ApiKeyGuard.name)
  private readonly apiKey: string

  constructor(private readonly configService: ConfigService) {
    this.apiKey = this.configService.get<string>('SECRET_API_KEY', '') // Default to empty if not found
    if (!this.apiKey) {
      this.logger.warn(
        'CRITICAL: SECRET_API_KEY is not configured or is empty. API key authentication will fail for all requests using this guard.'
      )
    }
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest()
    const providedApiKey = request.headers['x-api-key'] || request.query.apiKey

    // Case 1: Server is not configured with an API key (this.apiKey is empty).
    // The constructor already logs a warning for this. All such requests should fail.
    if (!this.apiKey) {
      // This log is optional as the constructor already warns. Kept for clarity during request processing if needed.
      // this.logger.error('API key authentication failed: Service is not configured with an API key.');
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
