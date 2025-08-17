import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'

@Injectable()
export class PaymentAPIKeyGuard implements CanActivate {
  constructor(private readonly configService: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest()
    const paymentApiKey = request.headers['authorization']?.split(' ')[1]
    if (paymentApiKey !== this.configService.get<string>('PAYMENT_API_KEY')) {
      throw new UnauthorizedException('Error.InvalidPaymentAPIKey')
    }
    return true
  }
}
