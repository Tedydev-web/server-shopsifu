import { Injectable, Logger } from '@nestjs/common'
import { CreateOrderBodyType, GetOrderListQueryType } from 'src/routes/order/order.model'
import { OrderRepo } from 'src/routes/order/order.repo'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { PricingService } from 'src/shared/services/pricing.service'
import { ShippingProducer } from 'src/shared/queue/producer/shipping.producer'
import { GHN_PAYMENT_TYPE } from 'src/shared/constants/shipping.constants'
import { OrderShippingStatus } from 'src/shared/constants/order-shipping.constants'
import {
  DiscountUsageLimitExceededException,
  DiscountNotApplicableException,
  DiscountExpiredException
} from 'src/routes/discount/discount.error'
import { normalizePhoneForGHN } from 'src/shared/helpers'
@Injectable()
export class OrderService {
  private readonly logger = new Logger(OrderService.name)

  constructor(
    private readonly orderRepo: OrderRepo,
    private readonly i18n: I18nService<I18nTranslations>,
    private readonly pricingService: PricingService,
    private readonly shippingProducer: ShippingProducer
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
    // Thu thập tất cả discount codes (shop + platform)
    const shopDiscountCodes = body.shops
      .filter((shop) => shop.discountCodes && Array.isArray(shop.discountCodes))
      .flatMap((shop) => shop.discountCodes)
      .filter((code): code is string => code !== undefined)

    const platformDiscountCodes = body.platformDiscountCodes || []
    const allDiscountCodes = [...shopDiscountCodes, ...platformDiscountCodes]

    if (allDiscountCodes.length > 0) {
      // Validate tất cả discounts thông qua Repository
      const discountInfo = await this.orderRepo.validateDiscounts(allDiscountCodes, user.userId)
      const { discounts, userUsageMap } = discountInfo

      for (const discount of discounts) {
        // Kiểm tra trạng thái và thời gian
        if (discount.discountStatus !== 'ACTIVE') {
          throw DiscountNotApplicableException
        }

        const now = new Date()
        if (now < discount.startDate || now > discount.endDate) {
          throw DiscountExpiredException
        }

        // Kiểm tra maxUses
        if (discount.maxUses > 0 && discount.usesCount >= discount.maxUses) {
          throw DiscountUsageLimitExceededException
        }

        // Kiểm tra maxUsesPerUser
        if (discount.maxUsesPerUser && discount.maxUsesPerUser > 0) {
          const usedCount = userUsageMap.get(discount.id) || 0
          if (usedCount >= discount.maxUsesPerUser) throw DiscountUsageLimitExceededException
        }
      }
    }

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

    const result = await this.orderRepo.create(user.userId, body.shops, body.platformDiscountCodes)

    await Promise.all(
      result.orders.map(async (order) => {
        const shop = body.shops.find((s) => s.shopId === order.shopId)
        if (!shop?.shippingInfo) return

        // Lấy shop info với address từ Repository
        const shopInfo = await this.orderRepo.getShopWithAddress(shop.shopId)
        const { shop: shopData, address: shopAddressRecord } = shopInfo

        const info = shop.shippingInfo

        const isCod = shop.isCod === true
        const shopPayment = perShopMap.get(shop.shopId)
        const codAmount = isCod ? (shopPayment?.payment ?? 0) : 0

        // Tạo OrderShipping record với trạng thái DRAFT để lưu thông tin shipping
        const orderShipping = await this.orderRepo.createOrderShipping({
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
            await this.orderRepo.updateOrderShippingStatus(order.id, OrderShippingStatus.ENQUEUED)
          } catch (error) {
            console.error('Failed to enqueue COD shipping order:', error)
          }
        }
        // Online payment: GHN order sẽ được tạo sau khi thanh toán thành công
        // thông qua webhook callback từ VNPay/Sepay
      })
    )

    return {
      message: this.i18n.t('order.order.success.CREATE_SUCCESS'),
      data: result
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
      const orderShipping = await this.orderRepo.getOrderShipping(result.data.id)

      if (orderShipping && orderShipping.shippingFee !== null) {
        result.data.totalShippingFee = orderShipping.shippingFee
        result.data.totalPayment =
          result.data.totalItemCost + orderShipping.shippingFee - result.data.totalVoucherDiscount
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
}
