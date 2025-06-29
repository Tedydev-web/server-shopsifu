import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { EnvConfigType } from 'src/shared/config'

@Injectable()
export class APIKeyGuard implements CanActivate {
  private readonly apiKey: string

  constructor(private readonly configService: ConfigService<EnvConfigType>) {
    this.apiKey = this.configService.get('app').apiKey
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest()
    const xAPIKey = request.headers['x-api-key']
    if (xAPIKey !== this.apiKey) {
      throw new UnauthorizedException()
    }
    return true
  }
}
