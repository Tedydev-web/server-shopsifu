import { Injectable } from '@nestjs/common'
import { CreateOrderBodyType, GetOrderListQueryType } from 'src/routes/order/order.model'
import { OrderRepo } from 'src/routes/order/order.repo'
import { SharedDiscountRepository } from 'src/shared/repositories/shared-discount.repo'
import { SharedShippingRepository } from 'src/shared/repositories/shared-shipping.repo'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { ShippingProducer } from 'src/shared/queue/producer/shipping.producer'
import { GHN_PAYMENT_TYPE } from 'src/shared/constants/shipping.constants'
import { OrderShippingStatus } from 'src/shared/constants/order-shipping.constants'
import { normalizePhoneForGHN } from 'src/shared/helpers'
import { PricingService } from 'src/shared/services/pricing.service'
@Injectable()
export class OrderService {
  constructor(
    private readonly orderRepo: OrderRepo,
    private readonly sharedDiscountRepo: SharedDiscountRepository,
    private readonly sharedShippingRepo: SharedShippingRepository,
    private readonly i18n: I18nService<I18nTranslations>,
    private readonly shippingProducer: ShippingProducer,
    private readonly pricingService: PricingService
  ) {}

  async list(user: AccessTokenPayload, query: GetOrderListQueryType) {
    const data = await this.orderRepo.list(user.userId, query)
    return {
      message: this.i18n.t('order.order.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
  }

  async create(user: AccessTokenPayload, body: CreateOrderBodyType) {
    const shopDiscountCodes = body.shops
      .filter((shop) => shop.discountCodes && Array.isArray(shop.discountCodes))
      .flatMap((shop) => shop.discountCodes)
      .filter((code): code is string => code !== undefined)

    const platformDiscountCodes = body.platformDiscountCodes || []
    const allDiscountCodes = [...shopDiscountCodes, ...platformDiscountCodes]

    if (allDiscountCodes.length > 0) {
      // Validate tất cả discounts thông qua SharedDiscountRepository
      const discountInfo = await this.sharedDiscountRepo.validateDiscountsForOrder(allDiscountCodes, user.userId)
      const { discounts, userUsageMap } = discountInfo

      for (const discount of discounts) {
        // Kiểm tra trạng thái và thời gian
        if (discount.discountStatus !== 'ACTIVE') {
          throw new Error('Discount not applicable')
        }

        const now = new Date()
        if (now < discount.startDate || now > discount.endDate) {
          throw new Error('Discount expired')
        }

        // Kiểm tra maxUses
        if (discount.maxUses > 0 && discount.usesCount >= discount.maxUses) {
          throw new Error('Discount usage limit exceeded')
        }

        // Kiểm tra maxUsesPerUser
        if (discount.maxUsesPerUser && discount.maxUsesPerUser > 0) {
          const usedCount = userUsageMap.get(discount.id) || 0
          if (usedCount >= discount.maxUsesPerUser) throw new Error('Discount usage limit exceeded')
        }
      }
    }

    // Tính toán pricing với discounts
    const calc = await this.pricingService.tinhTamTinhDonHang(user, {
      shops: body.shops.map((s) => ({
        shopId: s.shopId,
        cartItemIds: s.cartItemIds,
        shippingFee: s.shippingInfo?.shippingFee ?? 0,
        discountCodes: s.discountCodes
      })),
      platformDiscountCodes: body.platformDiscountCodes
    })
    const perShopMap = new Map<string, { payment: number; platformVoucherDiscount: number }>()
    ;(calc.shops || []).forEach((sh) =>
      perShopMap.set(sh.shopId, {
        payment: sh.payment,
        platformVoucherDiscount: sh.platformVoucherDiscount || 0
      })
    )

    // Tạo order đơn giản (không có discount logic)
    const result = await this.orderRepo.create(user.userId, body.shops)

    await Promise.all(
      result.orders.map(async (order) => {
        const shop = body.shops.find((s) => s.shopId === order.shopId)
        if (!shop?.shippingInfo) return

        // Lấy shop info với address từ Shared Shipping Repository
        const shopInfo = await this.sharedShippingRepo.getShopAddressForShipping(shop.shopId)
        const { shop: shopData, address: shopAddressRecord } = shopInfo

        const info = shop.shippingInfo

        const isCod = shop.isCod === true
        const shopPayment = perShopMap.get(shop.shopId)
        const codAmount = isCod ? (shopPayment?.payment ?? 0) : 0

        // Tạo OrderShipping record với trạng thái DRAFT để lưu thông tin shipping
        await this.sharedShippingRepo.createOrderShipping({
          orderId: order.id,
          serviceId: info.service_id,
          serviceTypeId: info.service_type_id,
          configFeeId: info.config_fee_id,
          extraCostId: info.extra_cost_id,
          weight: info.weight,
          length: info.length,
          width: info.width,
          height: info.height,
          shippingFee: info.shippingFee ?? 0,
          codAmount: codAmount,
          note: info.note,
          requiredNote: info.required_note || 'CHOTHUHANG',
          pickShift: info.pick_shift ? JSON.stringify(info.pick_shift) : null,
          status: OrderShippingStatus.DRAFT,
          fromAddress: shopAddressRecord.street || '',
          fromName: shopData.name,
          fromPhone: normalizePhoneForGHN(shopAddressRecord.phoneNumber || shopData.phoneNumber) || '0987654321',
          fromProvinceName: shopAddressRecord.province || '',
          fromDistrictName: shopAddressRecord.district || '',
          fromWardName: shopAddressRecord.ward || '',
          fromDistrictId: shopAddressRecord.districtId || 0,
          fromWardCode: shopAddressRecord.wardCode || '',
          toAddress: shop.receiver.address,
          toName: shop.receiver.name,
          toPhone: normalizePhoneForGHN(shop.receiver.phone),
          toDistrictId: shop.receiver.districtId || 0,
          toWardCode: shop.receiver.wardCode || ''
        })

        // Chỉ tạo GHN order ngay lập tức cho COD
        // Online payment sẽ tạo GHN order sau khi thanh toán thành công
        if (isCod) {
          try {
            await this.shippingProducer.enqueueCreateOrder({
              from_address: shopAddressRecord.street || '',
              from_name: shopData.name,
              from_phone: normalizePhoneForGHN(shopAddressRecord.phoneNumber || shopData.phoneNumber) || '0987654321',
              from_province_name: shopAddressRecord.province || '',
              from_district_name: shopAddressRecord.district || '',
              from_ward_name: shopAddressRecord.ward || '',

              to_name: shop.receiver.name,
              to_phone: normalizePhoneForGHN(shop.receiver.phone),
              to_address: shop.receiver.address,
              to_ward_code: shop.receiver.wardCode || '',
              to_district_id: shop.receiver.districtId || 0,

              client_order_code: `SSPX${order.id}`,
              cod_amount: codAmount,
              shippingFee: info.shippingFee ?? 0,
              content: undefined,
              weight: info.weight,
              length: info.length,
              width: info.width,
              height: info.height,
              pick_station_id: undefined,
              insurance_value: undefined,
              service_id: info.service_id,
              service_type_id: info.service_type_id,
              config_fee_id: info.config_fee_id,
              extra_cost_id: info.extra_cost_id,
              coupon: info.coupon ?? null,
              pick_shift: info.pick_shift,
              items: shop.cartItemIds.map((cartItemId) => ({
                name: `Item ${cartItemId.substring(0, 6)}`,
                quantity: 1,
                weight: info.weight,
                length: info.length,
                width: info.width,
                height: info.height
              })),
              payment_type_id: GHN_PAYMENT_TYPE.COD,
              note: info.note,
              required_note: info.required_note || 'CHOTHUHANG'
            })

            // Cập nhật trạng thái OrderShipping thành ENQUEUED
            await this.sharedShippingRepo.updateOrderShippingStatus(order.id, OrderShippingStatus.ENQUEUED)
          } catch (error) {
            console.error('Failed to enqueue COD shipping order:', error)
          }
        }
      })
    )

    // Cập nhật trạng thái COD orders thành PENDING_PACKAGING
    await this.updateCodOrdersStatus(result.orders, body.shops)

    // Fetch lại orders với status đã được cập nhật
    const updatedResult = await this.getUpdatedOrdersResult(result)

    return {
      message: this.i18n.t('order.order.success.CREATE_SUCCESS'),
      data: updatedResult
    }
  }

  async cancel(user: AccessTokenPayload, orderId: string) {
    const result = await this.orderRepo.cancel(user.userId, orderId)
    return {
      message: this.i18n.t('order.order.success.CANCEL_SUCCESS'),
      data: result.data
    }
  }

  async detail(user: AccessTokenPayload, orderId: string) {
    const result = await this.orderRepo.detail(user.userId, orderId)

    // Lấy shipping info từ OrderShipping
    if (result.data) {
      const [orderShipping, ghnOrderCode] = await Promise.all([
        this.sharedShippingRepo.getOrderShippingInfo(result.data.id),
        this.sharedShippingRepo.getGHNOrderCode(result.data.id)
      ])

      if (orderShipping && orderShipping.shippingFee !== null) {
        result.data.totalShippingFee = orderShipping.shippingFee
        result.data.totalPayment =
          result.data.totalItemCost + orderShipping.shippingFee - result.data.totalVoucherDiscount
      }

      if (ghnOrderCode) {
        ;(result.data as any).orderCode = ghnOrderCode
      }
    }

    return {
      message: this.i18n.t('order.order.success.GET_DETAIL_SUCCESS'),
      data: result.data
    }
  }

  async calculate(user: AccessTokenPayload, body: any) {
    const result = await this.pricingService.tinhTamTinhDonHang(user, {
      shops: body.shops,
      platformDiscountCodes: body.platformDiscountCodes
    })

    return {
      message: this.i18n.t('order.order.success.CALCULATE_SUCCESS'),
      data: result
    }
  }

  /**
   * Cập nhật trạng thái COD orders thành PENDING_PACKAGING
   */
  private async updateCodOrdersStatus(
    orders: Array<{ id: string; shopId: string | null }>,
    shops: Array<{ shopId: string; isCod?: boolean }>
  ) {
    console.log('Debug - Input orders:', orders.map(o => ({ id: o.id, shopId: o.shopId })))
    console.log('Debug - Input shops:', shops.map(s => ({ shopId: s.shopId, isCod: s.isCod })))
    
    const codOrderIds = orders
      .filter((order) => {
        if (!order.shopId) return false
        const shop = shops.find((s) => s.shopId === order.shopId)
        return shop?.isCod === true
      })
      .map((order) => order.id)

    console.log('Debug - COD Order IDs:', codOrderIds)

    if (codOrderIds.length > 0) {
      await this.orderRepo.updateMultipleOrdersStatus(codOrderIds, 'PENDING_PACKAGING')
      console.log('Debug - Updated COD orders to PENDING_PACKAGING')
    }
  }

  /**
   * Fetch lại orders với status đã được cập nhật
   */
  private async getUpdatedOrdersResult(originalResult: { paymentId: number; orders: any[] }) {
    const orderIds = originalResult.orders.map(order => order.id)
    const updatedOrders = await this.orderRepo.getOrdersByIds(orderIds)
    
    console.log('Debug - Original orders:', originalResult.orders.map(o => ({ id: o.id, status: o.status })))
    console.log('Debug - Updated orders:', updatedOrders.map(o => ({ id: o.id, status: o.status })))
    
    return {
      paymentId: originalResult.paymentId,
      orders: updatedOrders
    }
  }
}
