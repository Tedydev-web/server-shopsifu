import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { OrderShipping, OrderShippingStatus } from '@prisma/client'

@Injectable()
export class ShippingRepo {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Tìm shipping theo orderId
   */
  async findByOrderId(orderId: string): Promise<OrderShipping | null> {
    return this.prisma.orderShipping.findUnique({
      where: { orderId }
    })
  }

  /**
   * Tìm shipping theo orderCode
   */
  async findByOrderCode(orderCode: string): Promise<OrderShipping | null> {
    return this.prisma.orderShipping.findUnique({
      where: { orderCode }
    })
  }

  /**
   * Tạo hoặc cập nhật shipping
   */
  async upsertShipping(data: {
    orderId: string
    orderCode?: string
    serviceId?: number
    serviceTypeId?: number
    shippingFee?: number
    codAmount?: number
    expectedDeliveryTime?: Date
    trackingUrl?: string
    status?: OrderShippingStatus
    fromAddress?: string
    fromName?: string
    fromPhone?: string
    fromProvinceName?: string
    fromDistrictName?: string
    fromWardName?: string
    fromDistrictId?: number
    fromWardCode?: string
    toAddress?: string
    toName?: string
    toPhone?: string
    toDistrictId?: number
    toWardCode?: string
  }): Promise<OrderShipping> {
    const shippingData = {
      orderCode: data.orderCode,
      serviceId: data.serviceId,
      serviceTypeId: data.serviceTypeId,
      shippingFee: data.shippingFee,
      codAmount: data.codAmount,
      expectedDeliveryTime: data.expectedDeliveryTime,
      trackingUrl: data.trackingUrl,
      status: data.status,
      fromAddress: data.fromAddress,
      fromName: data.fromName,
      fromPhone: data.fromPhone,
      fromProvinceName: data.fromProvinceName,
      fromDistrictName: data.fromDistrictName,
      fromWardName: data.fromWardName,
      fromDistrictId: data.fromDistrictId,
      fromWardCode: data.fromWardCode,
      toAddress: data.toAddress,
      toName: data.toName,
      toPhone: data.toPhone,
      toDistrictId: data.toDistrictId,
      toWardCode: data.toWardCode
    }

    return this.prisma.orderShipping.upsert({
      where: { orderId: data.orderId },
      create: { orderId: data.orderId, ...shippingData },
      update: shippingData
    })
  }

  /**
   * Cập nhật trạng thái shipping
   */
  async updateStatus(orderId: string, status: OrderShippingStatus): Promise<OrderShipping> {
    return this.prisma.orderShipping.update({
      where: { orderId },
      data: { status }
    })
  }

  /**
   * Cập nhật trạng thái order khi shipping thay đổi
   */
  async updateOrderStatus(orderId: string, status: OrderShippingStatus): Promise<void> {
    const orderStatusMap: Record<string, 'PENDING_DELIVERY' | 'DELIVERED' | 'CANCELLED'> = {
      DELIVERED: 'DELIVERED',
      PICK: 'PENDING_DELIVERY',
      PENDING: 'PENDING_DELIVERY',
      CANCEL: 'CANCELLED'
    }

    const orderStatus = Object.entries(orderStatusMap).find(([key]) => status.includes(key))?.[1]

    if (orderStatus) {
      await this.prisma.order.update({
        where: { id: orderId },
        data: { status: orderStatus }
      })
    }
  }
}
