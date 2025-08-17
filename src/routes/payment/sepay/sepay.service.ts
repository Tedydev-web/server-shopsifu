import { Injectable } from '@nestjs/common'
import { SepayRepo } from 'src/routes/payment/sepay/sepay.repo'
import { WebhookPaymentBodyType } from 'src/routes/payment/sepay/sepay.model'
import { SharedWebsocketRepository } from 'src/shared/repositories/shared-websocket.repo'
import { WebSocketGateway, WebSocketServer } from '@nestjs/websockets'
import { Server } from 'socket.io'
import { generateRoomPaymentId } from 'src/shared/helpers'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
@WebSocketGateway({ namespace: 'payment' })
export class SepayService {
  @WebSocketServer()
  server: Server
  constructor(
    private readonly sepayRepo: SepayRepo,
    private readonly sharedWebsocketRepository: SharedWebsocketRepository,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async receiver(body: WebhookPaymentBodyType) {
    try {
      const { userId, paymentId } = await this.sepayRepo.receiver(body)

      // Emit success event cho payment room (chỉ client nào join payment room mới nhận)
      this.server.to(generateRoomPaymentId(paymentId)).emit('payment', {
        status: 'success',
        gateway: 'sepay',
        paymentId
      })

      return {
        message: this.i18n.t('payment.payment.sepay.success.RECEIVER_SUCCESS')
      }
    } catch (error) {
      // Nếu có lỗi (amount mismatch, payment not found, etc.)
      // Không emit event vì đây là lỗi validation
      throw error
    }
  }
}
