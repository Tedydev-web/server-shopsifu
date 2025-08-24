import { Injectable, BadRequestException, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { OrderShippingStatusType } from 'src/shared/constants/order-shipping.constants'
import { normalizePhoneForGHN } from 'src/shared/helpers'

type CreateOrderShippingData = {
  orderId: string
  serviceId?: number
  serviceTypeId?: number
  configFeeId?: string
  extraCostId?: string
  weight?: number
  length?: number
  width?: number
  height?: number
  shippingFee: number
  codAmount: number
  note?: string
  requiredNote?: string
  pickShift?: any
  status?: OrderShippingStatusType
  fromAddress: string
  fromName: string
  fromPhone: string
  fromProvinceName: string
  fromDistrictName: string
  fromWardName: string
  fromDistrictId: number
  fromWardCode: string
  toAddress: string
  toName: string
  toPhone: string
  toDistrictId: number
  toWardCode: string
}

type ShopAddressInfo = {
  shop: any
  address: any
}

type OrderForShippingData = {
  order: any
  items: any[]
  shop: any
  shopAddress: any
}

@Injectable()
export class SharedShippingRepository {
  private readonly logger = new Logger(SharedShippingRepository.name)

  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Tạo OrderShipping record - Bridge method
   * Sử dụng bởi Order module để tạo shipping record khi tạo order
   */
  async createOrderShipping(data: CreateOrderShippingData) {
    this.logger.log(`[SHARED_SHIPPING] Bắt đầu tạo OrderShipping record cho order: ${data.orderId}`)
    this.logger.log(`[SHARED_SHIPPING] OrderShipping data: ${JSON.stringify(data, null, 2)}`)

    try {
      const orderShipping = await this.prismaService.orderShipping.create({
        data: {
          orderId: data.orderId,
          serviceId: data.serviceId,
          serviceTypeId: data.serviceTypeId,
          configFeeId: data.configFeeId,
          extraCostId: data.extraCostId,
          weight: data.weight,
          length: data.length,
          width: data.width,
          height: data.height,
          shippingFee: data.shippingFee,
          codAmount: data.codAmount,
          expectedDeliveryTime: null,
          trackingUrl: null,
          status: data.status,
          note: data.note,
          requiredNote: data.requiredNote,
          pickShift: data.pickShift,
          attempts: 0,
          lastError: null,
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
      })

      this.logger.log(`[SHARED_SHIPPING] OrderShipping created successfully: ${JSON.stringify(orderShipping, null, 2)}`)
      return orderShipping
    } catch (error) {
      this.logger.error(`[SHARED_SHIPPING] Lỗi khi tạo OrderShipping: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Cập nhật trạng thái OrderShipping - Bridge method
   * Sử dụng bởi Order module để cập nhật shipping status
   */
  async updateOrderShippingStatus(orderId: string, status: OrderShippingStatusType) {
    this.logger.log(`[SHARED_SHIPPING] Cập nhật OrderShipping status cho order: ${orderId} thành: ${status}`)

    try {
      const result = await this.prismaService.orderShipping.update({
        where: { orderId },
        data: { status }
      })

      this.logger.log(`[SHARED_SHIPPING] OrderShipping status updated successfully: ${JSON.stringify(result, null, 2)}`)
      return result
    } catch (error) {
      this.logger.error(`[SHARED_SHIPPING] Lỗi khi cập nhật OrderShipping status: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Lấy shipping info của order - Bridge method
   * Sử dụng bởi Order module để lấy shipping info khi hiển thị
   */
  async getOrderShippingInfo(orderId: string) {
    return this.prismaService.orderShipping.findUnique({
      where: { orderId }
    })
  }

  /**
   * Lấy GHN order code từ order ID - Bridge method
   * Sử dụng bởi Order module để trả về cho client
   */
  async getGHNOrderCode(orderId: string): Promise<string | null> {
    const orderShipping = await this.prismaService.orderShipping.findUnique({
      where: { orderId },
      select: { orderCode: true, status: true }
    })

    // Chỉ trả về orderCode nếu shipping đã được tạo thành công
    if (orderShipping?.status === 'CREATED' && orderShipping.orderCode) {
      return orderShipping.orderCode
    }

    return null
  }

  /**
   * Lấy shop info với address để tạo shipping - Bridge method
   * Sử dụng bởi Shipping module để lấy shop address
   */
  async getShopAddressForShipping(shopId: string): Promise<ShopAddressInfo> {
    this.logger.log(`[SHARED_SHIPPING] Lấy shop address cho shop: ${shopId}`)

    try {
      const shopData = await this.prismaService.user.findUnique({
        where: { id: shopId }
      })

      if (!shopData) {
        this.logger.error(`[SHARED_SHIPPING] Shop không tồn tại: ${shopId}`)
        throw new BadRequestException('Shop not found')
      }

      this.logger.log(`[SHARED_SHIPPING] Shop data: ${JSON.stringify(shopData, null, 2)}`)

      // Lấy shop address từ UserAddress
      this.logger.log(`[SHARED_SHIPPING] Lấy shop address từ UserAddress`)
      const shopUserAddress = await this.prismaService.userAddress.findFirst({
        where: { userId: shopId, isDefault: true },
        include: { address: true }
      })

      if (!shopUserAddress || !shopUserAddress.address) {
        this.logger.error(`[SHARED_SHIPPING] Shop address không tồn tại cho shop: ${shopId}`)
        throw new BadRequestException('Shop address not found')
      }

      this.logger.log(`[SHARED_SHIPPING] Shop address: ${JSON.stringify(shopUserAddress.address, null, 2)}`)

      const result = {
        shop: shopData,
        address: shopUserAddress.address
      }

      this.logger.log(`[SHARED_SHIPPING] Shop address info: ${JSON.stringify(result, null, 2)}`)
      return result
    } catch (error) {
      this.logger.error(`[SHARED_SHIPPING] Lỗi khi lấy shop address: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Lấy order data cho shipping - Bridge method
   * Sử dụng bởi Shipping module để lấy order data khi tạo GHN order
   */
  async getOrderForShipping(orderId: string): Promise<OrderForShippingData | null> {
    const order = await this.prismaService.order.findUnique({
      where: {
        id: orderId,
        deletedAt: null
      },
      include: {
        items: true,
        shop: {
          include: {
            UserAddress: {
              where: { isDefault: true },
              include: { address: true }
            }
          }
        }
      }
    })

    if (!order) {
      return null
    }

    const shopAddress = order.shop?.UserAddress?.[0]?.address
    if (!shopAddress) {
      throw new BadRequestException('Shop address not found')
    }

    return {
      order,
      items: order.items,
      shop: order.shop,
      shopAddress
    }
  }

  /**
   * Lấy order items cho shipping - Bridge method
   * Sử dụng bởi Shipping module để lấy order items khi tạo GHN order
   */
  async getOrderItemsForShipping(orderIds: string[]) {
    return this.prismaService.productSKUSnapshot.findMany({
      where: { orderId: { in: orderIds } }
    })
  }

  /**
   * Lấy shop addresses cho shipping - Bridge method
   * Sử dụng bởi Shipping module để lấy shop addresses khi tạo GHN orders
   */
  async getShopAddressesForShipping(shopIds: string[]) {
    return this.prismaService.userAddress.findMany({
      where: { userId: { in: shopIds }, isDefault: true },
      include: { address: true }
    })
  }

  /**
   * Lấy order với shipping để hiển thị - Bridge method
   * Sử dụng bởi Order module để hiển thị order với shipping info
   */
  async getOrderWithShippingForDisplay(orderId: string, userId: string) {
    return this.prismaService.order.findUnique({
      where: {
        id: orderId,
        userId,
        deletedAt: null
      },
      include: {
        items: true,
        discounts: true,
        shipping: true
      }
    })
  }

  /**
   * Lấy OrderShipping info cho order - Bridge method
   * Sử dụng bởi Order module để kiểm tra GHN order status
   */
  async getOrderShippingForCancellation(orderId: string) {
    return this.prismaService.orderShipping.findUnique({
      where: { orderId },
      select: {
        id: true,
        orderCode: true,
        status: true,
        orderId: true
      }
    })
  }

  /**
   * Update OrderShipping status - Bridge method
   * Sử dụng bởi Order module để update status khi cancel order
   */
  async updateOrderShippingStatusForCancellation(
    orderId: string,
    status: OrderShippingStatusType,
    errorMessage?: string
  ) {
    return this.prismaService.orderShipping.update({
      where: { orderId },
      data: {
        status,
        lastError: errorMessage,
        lastUpdatedAt: new Date()
      }
    })
  }

  /**
   * Lấy order với shipping cho GHN - Bridge method
   * Sử dụng bởi Shipping module để lấy order data cho GHN API
   */
  async getOrderWithShippingForGHN(orderId: string) {
    return this.prismaService.order.findUnique({
      where: {
        id: orderId,
        deletedAt: null
      },
      include: {
        items: true,
        discounts: true,
        shipping: true,
        shop: {
          include: {
            UserAddress: {
              where: { isDefault: true },
              include: { address: true }
            }
          }
        }
      }
    })
  }

  /**
   * Chuẩn bị shipping data cho GHN - Bridge method
   * Sử dụng bởi Shipping module để chuẩn bị data cho GHN API
   */
  prepareShippingDataForGHN(order: any, shopAddress: any, shippingInfo: any, codAmount: number) {
    return {
      from_address: shopAddress.street || '',
      from_name: order.shop.name,
      from_phone: normalizePhoneForGHN(shopAddress.phoneNumber || order.shop.phoneNumber) || '0987654321',
      from_province_name: shopAddress.province || '',
      from_district_name: shopAddress.district || '',
      from_ward_name: shopAddress.ward || '',

      to_name: order.receiver.name,
      to_phone: normalizePhoneForGHN(order.receiver.phone),
      to_address: order.receiver.address,
      to_ward_code: order.receiver.wardCode || '',
      to_district_id: order.receiver.districtId || 0,

      client_order_code: `SSPX${order.id}`,
      cod_amount: codAmount,
      shippingFee: shippingInfo.shippingFee ?? 0,
      content: undefined,
      weight: shippingInfo.weight,
      length: shippingInfo.length,
      width: shippingInfo.width,
      height: shippingInfo.height,
      pick_station_id: undefined,
      insurance_value: undefined,
      service_id: shippingInfo.service_id,
      service_type_id: shippingInfo.service_type_id,
      config_fee_id: shippingInfo.config_fee_id,
      extra_cost_id: shippingInfo.extra_cost_id,
      coupon: shippingInfo.coupon ?? null,
      pick_shift: shippingInfo.pick_shift,
      items: order.items.map((item: any) => ({
        name: `Item ${item.id.substring(0, 6)}`,
        quantity: item.quantity,
        weight: shippingInfo.weight,
        length: shippingInfo.length,
        width: shippingInfo.width,
        height: shippingInfo.height
      })),
      payment_type_id: codAmount > 0 ? 2 : 1, // 2: COD, 1: Online
      note: shippingInfo.note,
      required_note: shippingInfo.required_note || 'CHOTHUHANG'
    }
  }
}
