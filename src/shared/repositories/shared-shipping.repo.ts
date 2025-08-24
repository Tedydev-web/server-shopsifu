import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { OrderShippingStatusType } from 'src/shared/constants/order-shipping.constants'
import { ShippingProducer } from 'src/shared/queue/producer/shipping.producer'

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

@Injectable()
export class SharedShippingRepository {
  private readonly logger = new Logger(SharedShippingRepository.name)

  constructor(
    private readonly prismaService: PrismaService,
    private readonly shippingProducer: ShippingProducer
  ) {}

  /**
   * Tạo OrderShipping record - Bridge method
   * Sử dụng bởi Order module để tạo shipping record khi tạo order
   */
  async createOrderShipping(data: CreateOrderShippingData) {
    this.logger.log(`[SHARED_SHIPPING] Bắt đầu tạo OrderShipping record cho order: ${data.orderId}`)

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
   * Hủy đơn hàng GHN - Bridge method
   * Sử dụng bởi Order module để hủy đơn hàng GHN khi cancel order
   */
  async cancelGHNOrderForOrder(orderId: string): Promise<{ success: boolean; message: string }> {
    try {
      this.logger.log(`[SHARED_SHIPPING] Bắt đầu hủy đơn hàng GHN cho order: ${orderId}`)

      // Lấy thông tin OrderShipping
      const orderShipping = await this.prismaService.orderShipping.findUnique({
        where: { orderId },
        select: { orderCode: true, status: true }
      })

      if (!orderShipping?.orderCode) {
        this.logger.warn(`[SHARED_SHIPPING] Không có orderCode cho order: ${orderId}`)
        return {
          success: false,
          message: 'Không có mã đơn hàng GHN để hủy'
        }
      }

      if (orderShipping.status !== 'CREATED') {
        this.logger.warn(`[SHARED_SHIPPING] OrderShipping status không phù hợp để hủy: ${orderShipping.status}`)
        return {
          success: false,
          message: `Trạng thái đơn hàng không phù hợp để hủy: ${orderShipping.status}`
        }
      }

      // Enqueue job để hủy đơn hàng GHN
      await this.shippingProducer.enqueueCancelGHNOrder(orderShipping.orderCode, orderId)

      this.logger.log(`[SHARED_SHIPPING] Đã enqueue job hủy đơn hàng GHN: ${orderShipping.orderCode}`)

      return {
        success: true,
        message: `Đã enqueue job hủy đơn hàng GHN: ${orderShipping.orderCode}`
      }
    } catch (error) {
      this.logger.error(`[SHARED_SHIPPING] Lỗi khi hủy đơn hàng GHN: ${error.message}`)
      return {
        success: false,
        message: `Lỗi khi hủy đơn hàng GHN: ${error.message}`
      }
    }
  }

  /**
   * Lấy shop info với address để tạo shipping - Bridge method
   * Sử dụng bởi Shipping module để lấy shop address
   */
  async getShopAddressForShipping(shopId: string): Promise<{ shop: any; address: any }> {
    this.logger.log(`[SHARED_SHIPPING] Lấy shop address cho shop: ${shopId}`)

    try {
      // 1. Kiểm tra shop có tồn tại không
      const shopData = await this.prismaService.user.findUnique({
        where: { id: shopId }
      })

      if (!shopData) {
        this.logger.error(`[SHARED_SHIPPING] Shop không tồn tại: ${shopId}`)
        throw new Error('Shop not found')
      }

      this.logger.log(`[SHARED_SHIPPING] Shop data: ${JSON.stringify(shopData, null, 2)}`)

      // 2. Lấy shop address từ UserAddress (default address trước, fallback về bất kỳ address nào)
      this.logger.log(`[SHARED_SHIPPING] Lấy shop default address từ UserAddress`)
      let shopUserAddress = await this.prismaService.userAddress.findFirst({
        where: { userId: shopId, isDefault: true },
        include: { address: true }
      })

      // Nếu không có default address, lấy address đầu tiên
      if (!shopUserAddress) {
        this.logger.warn(
          `[SHARED_SHIPPING] Shop không có default address, thử lấy address đầu tiên cho shop: ${shopId}`
        )
        shopUserAddress = await this.prismaService.userAddress.findFirst({
          where: { userId: shopId },
          include: { address: true }
        })
      }

      if (!shopUserAddress) {
        this.logger.error(`[SHARED_SHIPPING] Shop không có bất kỳ address nào cho shop: ${shopId}`)
        throw new Error('Shop has no addresses')
      }

      if (!shopUserAddress.address) {
        this.logger.error(`[SHARED_SHIPPING] Shop address record không có address data cho shop: ${shopId}`)
        throw new Error('Shop address data not found')
      }

      this.logger.log(`[SHARED_SHIPPING] Shop UserAddress: ${JSON.stringify(shopUserAddress, null, 2)}`)
      this.logger.log(`[SHARED_SHIPPING] Shop address: ${JSON.stringify(shopUserAddress.address, null, 2)}`)

      // 3. Kiểm tra address có đầy đủ thông tin không
      if (!shopUserAddress.address.province || !shopUserAddress.address.district || !shopUserAddress.address.ward) {
        this.logger.error(`[SHARED_SHIPPING] Shop address thiếu thông tin địa chỉ cho shop: ${shopId}`)
        throw new Error('Shop address missing required location information')
      }

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
   * Tạo đơn hàng GHN - Bridge method
   * Sử dụng bởi Payment webhook để tạo đơn hàng GHN sau khi thanh toán thành công
   */
  async createGHNOrderForOrder(orderId: string): Promise<{ success: boolean; message: string }> {
    try {
      this.logger.log(`[SHARED_SHIPPING] Bắt đầu tạo đơn hàng GHN cho order: ${orderId}`)

      // Lấy thông tin OrderShipping
      const orderShipping = await this.prismaService.orderShipping.findUnique({
        where: { orderId },
        select: { status: true }
      })

      if (!orderShipping) {
        this.logger.warn(`[SHARED_SHIPPING] Không tìm thấy OrderShipping cho order: ${orderId}`)
        return {
          success: false,
          message: 'Không tìm thấy thông tin vận chuyển'
        }
      }

      if (orderShipping.status !== 'DRAFT') {
        this.logger.warn(
          `[SHARED_SHIPPING] OrderShipping status không phù hợp để tạo GHN order: ${orderShipping.status}`
        )
        return {
          success: false,
          message: `Trạng thái vận chuyển không phù hợp để tạo GHN order: ${orderShipping.status}`
        }
      }

      // Enqueue job để tạo đơn hàng GHN
      await this.shippingProducer.enqueueCreateGHNOrder(orderId)

      this.logger.log(`[SHARED_SHIPPING] Đã enqueue job tạo đơn hàng GHN cho order: ${orderId}`)

      return {
        success: true,
        message: `Đã enqueue job tạo đơn hàng GHN cho order: ${orderId}`
      }
    } catch (error) {
      this.logger.error(`[SHARED_SHIPPING] Lỗi khi tạo đơn hàng GHN: ${error.message}`)
      return {
        success: false,
        message: `Lỗi khi tạo đơn hàng GHN: ${error.message}`
      }
    }
  }
}
