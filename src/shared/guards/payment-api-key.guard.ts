import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common'

@Injectable()
export class PaymentAPIKeyGuard implements CanActivate {
	canActivate(context: ExecutionContext): boolean {
		const request = context.switchToHttp().getRequest()
		const paymentApiKey = request.headers['payment-api-key']
		if (paymentApiKey !== process.env.PAYMENT_API_KEY) {
			throw new UnauthorizedException()
		}
		return true
	}
}
