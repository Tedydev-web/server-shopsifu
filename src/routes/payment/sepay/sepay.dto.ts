import { createZodDto } from 'nestjs-zod'
import { WebhookPaymentBodySchema } from 'src/routes/payment/sepay/sepay.model'

export class WebhookPaymentBodyDTO extends createZodDto(WebhookPaymentBodySchema) {}
