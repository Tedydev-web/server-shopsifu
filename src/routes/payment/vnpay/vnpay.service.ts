import { Injectable } from '@nestjs/common'
import { WebSocketGateway, WebSocketServer } from '@nestjs/websockets'
import { Server } from 'socket.io'
import { VNPayRepo } from 'src/routes/payment/vnpay/vnpay.repo'
import {
  CreateVNPayPaymentUrlType,
  VNPayReturnUrlType,
  VNPayIpnType,
  CreateVNPayPaymentUrlResType
} from 'src/routes/payment/vnpay/vnpay.model'
import { SharedWebsocketRepository } from 'src/shared/repositories/shared-websocket.repo'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { generateRoomUserId } from 'src/shared/helpers'

@Injectable()
@WebSocketGateway({ namespace: 'payment' })
export class VNPayService {
  @WebSocketServer()
  server: Server

  constructor(
    private readonly vnpayRepo: VNPayRepo,
    private readonly sharedWebsocketRepository: SharedWebsocketRepository,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async createPaymentUrl(body: CreateVNPayPaymentUrlType): Promise<CreateVNPayPaymentUrlResType> {
    const paymentUrl = this.vnpayRepo.createPaymentUrl(body)
    return { paymentUrl }
  }

  async handleReturnUrl(query: VNPayReturnUrlType) {
    const userId = await this.vnpayRepo.handleReturnUrl(query)

    // Send WebSocket notification
    this.server.to(generateRoomUserId(userId)).emit('payment', {
      status: 'success',
      gateway: 'vnpay'
    })

    return {
      message: this.i18n.t('payment.payment.success.RETURN_URL_SUCCESS')
    }
  }

  async handleIpnCall(body: VNPayIpnType) {
    return this.vnpayRepo.handleIpnCall(body)
  }
}
