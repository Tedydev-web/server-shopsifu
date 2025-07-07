import { createZodDto } from 'nestjs-zod'

import { WebhookPaymentBodySchema } from 'src/routes/payment/payment.model'

export class WebhookPaymentBodyDTO extends createZodDto(WebhookPaymentBodySchema) {}
