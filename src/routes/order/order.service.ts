import { Injectable } from '@nestjs/common'
import { CreateOrderBodyType, GetOrderListQueryType } from 'src/routes/order/order.model'
import { OrderRepo } from 'src/routes/order/order.repo'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { PricingService } from 'src/shared/services/pricing.service'
import { ShippingProducer } from 'src/shared/queue/producer/shipping.producer'
import { GHN_PAYMENT_TYPE } from 'src/shared/constants/shipping.constants'
import {
  DiscountUsageLimitExceededException,
  DiscountNotApplicableException,
  DiscountExpiredException
} from 'src/routes/discount/discount.error'
@Injectable()
export class OrderService {
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
    // Thu thập tất cả discount codes
    const allDiscountCodes = body
      .filter((shop) => shop.discountCodes && Array.isArray(shop.discountCodes))
      .flatMap((shop) => shop.discountCodes)
      .filter((code): code is string => code !== undefined)

    if (allDiscountCodes.length > 0) {
      // Validate discounts thông qua Repository
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

    // Tính tạm tính để lấy breakdown per shop (itemCost, shippingFee, voucher allocation, payment)
    const calc = await this.pricingService.tinhTamTinhDonHang(user, {
      shops: body.map((s) => ({
        shopId: s.shopId,
        cartItemIds: s.cartItemIds,
        shippingFee: s.shippingInfo?.shippingFee ?? 0,
        discountCodes: s.discountCodes
      })),
      platformDiscountCodes: []
    })
    const perShopMap = new Map<string, { payment: number }>()
    ;(calc.shops || []).forEach((sh) => perShopMap.set(sh.shopId, { payment: sh.payment }))

    const result = await this.orderRepo.create(user.userId, body)

    // Lưu shipping info trực tiếp vào order và tạo OrderShipping record
    await Promise.all(
      result.orders.map(async (order) => {
        const shop = body.find((s) => s.shopId === order.shopId)
        if (!shop?.shippingInfo) return

        // Lấy shop info với address từ Repository
        const shopInfo = await this.orderRepo.getShopWithAddress(shop.shopId)
        const { shop: shopData, address: shopAddressRecord } = shopInfo

        const info = shop.shippingInfo
        const isCod = shop.isCod === true
        const codAmount = isCod ? (perShopMap.get(shop.shopId)?.payment ?? 0) : 0

        // Tạo OrderShipping record thông qua Repository
        try {
          await this.orderRepo.createOrderShipping({
            orderId: order.id,
            serviceId: info.service_id,
            serviceTypeId: info.service_type_id,
            shippingFee: info.shippingFee,
            codAmount: codAmount,
            fromAddress: shopAddressRecord.street || '',
            fromName: shopData.name,
            fromPhone: shopData.phoneNumber || '',
            fromProvinceName: shopAddressRecord.province || '',
            fromDistrictName: shopAddressRecord.district || '',
            fromWardName: shopAddressRecord.ward || '',
            fromDistrictId: shopAddressRecord.districtId || 0,
            fromWardCode: shopAddressRecord.wardCode || '',
            toAddress: shop.receiver.address,
            toName: shop.receiver.name,
            toPhone: shop.receiver.phone,
            toDistrictId: 0, // Không có GHN ID cho user address
            toWardCode: '' // Không có GHN ID cho user address
          })
        } catch (error) {
          console.error('Failed to create OrderShipping record:', error)
        }

        // Enqueue job để tạo GHN order với thông tin từ address
        try {
          await this.shippingProducer.enqueueCreateOrder({
            // Sử dụng SHOP address từ shopId (tự động lấy)
            from_address: shopAddressRecord.street || '',
            from_name: shopData.name,
            from_phone: shopData.phoneNumber || '',
            from_province_name: shopAddressRecord.province || '',
            from_district_name: shopAddressRecord.district || '',
            from_ward_name: shopAddressRecord.ward || '',

            // Sử dụng thông tin từ receiver (text address)
            to_name: shop.receiver.name,
            to_phone: shop.receiver.phone,
            to_address: shop.receiver.address,
            to_ward_code: '', // Không có GHN ID
            to_district_id: 0, // Không có GHN ID

            client_order_code: order.id,
            cod_amount: codAmount,
            content: undefined,
            weight: info.weight,
            length: info.length,
            width: info.width,
            height: info.height,
            pick_station_id: undefined,
            insurance_value: undefined,
            service_id: info.service_id,
            service_type_id: info.service_type_id,
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
            payment_type_id: isCod ? GHN_PAYMENT_TYPE.COD : GHN_PAYMENT_TYPE.PREPAID,
            note: info.note,
            required_note: info.required_note || 'CHOTHUHANG'
          })
        } catch (error) {
          console.error('Failed to enqueue shipping order:', error)
        }
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
