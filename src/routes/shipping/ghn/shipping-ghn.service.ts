import { Injectable, Inject, BadRequestException, Logger } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { Ghn } from 'giaohangnhanh'
import { SharedOrderRepository } from 'src/shared/repositories/shared-order.repo'
import { PrismaService } from 'src/shared/services/prisma.service'
import {
  GetProvincesResType,
  GetDistrictsResType,
  GetWardsResType,
  GetDistrictsQueryType,
  GetWardsQueryType,
  GetServiceListResType,
  CalculateShippingFeeResType,
  GetServiceListQueryType,
  CalculateShippingFeeType,
  CalculateExpectedDeliveryTimeType,
  CalculateExpectedDeliveryTimeResType,
  GHNWebhookPayloadType,
  GetOrderInfoQueryType,
  GetOrderInfoResType,
  GetTrackingUrlQueryType,
  GetTrackingUrlResType
} from './shipping-ghn.model'
import {
  ShippingServiceUnavailableException,
  InvalidProvinceIdException,
  InvalidDistrictIdException,
  MissingWardCodeException,
  InvalidDimensionsException,
  MissingServiceIdentifierException,
  InvalidWebhookPayloadException,
  ShippingOrderNotFoundException
} from './shipping-ghn.error'
import { GHN_CLIENT } from 'src/shared/constants/shipping.constants'
import { ShippingRepo } from './shipping-ghn.repo'
import { OrderShippingStatusType } from 'src/shared/constants/order-shipping.constants'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Injectable()
export class ShippingService {
  private readonly logger = new Logger(ShippingService.name)

  constructor(
    private readonly i18n: I18nService,
    @Inject(GHN_CLIENT) private readonly ghnService: Ghn,
    private readonly shippingRepo: ShippingRepo,
    private readonly sharedOrderRepo: SharedOrderRepository,
    private readonly prismaService: PrismaService
  ) {}

  private async detectUserAddresses(
    user: AccessTokenPayload,
    cartItemId?: string
  ): Promise<{
    fromDistrictId: number
    fromWardCode: string
    toDistrictId: number
    toWardCode: string
  }> {
    try {
      const userAddress = await this.prismaService.userAddress.findFirst({
        where: {
          userId: user.userId,
          isDefault: true
        },
        include: { address: true }
      })

      if (!userAddress || !userAddress.address) {
        this.logger.error(`❌ User default address not found for userId: ${user.userId}`)
        throw new BadRequestException('User default address not found')
      }

      const shopAddress = await this.findShopAddress(user.userId, cartItemId)

      if (!shopAddress) {
        this.logger.error(`❌ Cannot determine shop address. Please provide cartItemId.`)
        throw new BadRequestException('Không thể xác định địa chỉ shop. Vui lòng truyền cartItemId.')
      }

      const result = {
        fromDistrictId: shopAddress.address.districtId || 0,
        fromWardCode: shopAddress.address.wardCode || '',
        toDistrictId: userAddress.address.districtId || 0,
        toWardCode: userAddress.address.wardCode || ''
      }
      return result
    } catch (error) {
      throw error
    }
  }

  /**
   * Tìm shop address theo thứ tự ưu tiên
   */
  private async findShopAddress(userId: string, cartItemId?: string): Promise<any> {
    if (cartItemId) {
      const cartItem = await this.prismaService.cartItem.findFirst({
        where: {
          id: cartItemId,
          userId: userId
        },
        include: {
          sku: {
            include: {
              product: {
                select: {
                  id: true,
                  createdById: true
                }
              }
            }
          }
        }
      })

      if (cartItem) {
        const shopId = cartItem.sku?.product?.createdById
        if (shopId) {
          const shopUserAddress = await this.prismaService.userAddress.findFirst({
            where: { userId: shopId, isDefault: true },
            include: { address: true }
          })
          if (shopUserAddress?.address) {
            return { address: shopUserAddress.address }
          }
        }
      }
    }

    return null
  }

  /**
   * Xử lý error chung cho GHN API calls
   */
  private handleGHNError(error: any, specificExceptions: any[] = []): never {
    if (specificExceptions.includes(error)) {
      throw error
    }
    throw ShippingServiceUnavailableException
  }

  async getProvinces(): Promise<GetProvincesResType> {
    try {
      const provinces = await this.ghnService.address.getProvinces()

      return {
        message: this.i18n.t('ship.success.GET_PROVINCES_SUCCESS'),
        data: provinces
      }
    } catch (error) {
      this.handleGHNError(error)
    }
  }

  async getDistricts(query: GetDistrictsQueryType): Promise<GetDistrictsResType> {
    try {
      const { provinceId } = query

      if (!provinceId || provinceId <= 0) {
        throw InvalidProvinceIdException
      }

      const districts = await this.ghnService.address.getDistricts(provinceId)

      return {
        message: this.i18n.t('ship.success.GET_DISTRICTS_SUCCESS'),
        data: districts
      }
    } catch (error) {
      this.handleGHNError(error, [InvalidProvinceIdException])
    }
  }

  async getWards(query: GetWardsQueryType): Promise<GetWardsResType> {
    try {
      const { districtId } = query

      if (!districtId || districtId <= 0) {
        throw InvalidDistrictIdException
      }

      const wards = await this.ghnService.address.getWards(districtId)

      return {
        message: this.i18n.t('ship.success.GET_WARDS_SUCCESS'),
        data: wards
      }
    } catch (error) {
      this.handleGHNError(error, [InvalidDistrictIdException])
    }
  }

  async getServiceList(query: GetServiceListQueryType, user: AccessTokenPayload): Promise<GetServiceListResType> {
    try {
      const { cartItemId } = query

      const detectedAddresses = await this.detectUserAddresses(user, cartItemId)
      const fromDistrictId = detectedAddresses.fromDistrictId
      const toDistrictId = detectedAddresses.toDistrictId

      if (!fromDistrictId || fromDistrictId <= 0) {
        throw InvalidDistrictIdException
      }

      if (!toDistrictId || toDistrictId <= 0) {
        throw InvalidDistrictIdException
      }

      const services = await this.ghnService.calculateFee.getServiceList(fromDistrictId, toDistrictId)

      const normalized = services.map((s: any) => ({
        ...s,
        config_fee_id: s.config_fee_id === '' ? null : s.config_fee_id,
        extra_cost_id: s.extra_cost_id === '' ? null : s.extra_cost_id,
        standard_config_fee_id: s.standard_config_fee_id === '' ? null : s.standard_config_fee_id,
        standard_extra_cost_id: s.standard_extra_cost_id === '' ? null : s.standard_extra_cost_id
      }))

      return {
        message: this.i18n.t('ship.success.GET_SERVICE_LIST_SUCCESS'),
        data: normalized
      }
    } catch (error) {
      this.handleGHNError(error, [InvalidDistrictIdException])
    }
  }

  /**
   * Tính phí vận chuyển với auto-detection hoàn toàn
   * 🎯 Logic: Sử dụng cartItemIds để xác định shop và user address
   */
  async calculateShippingFee(
    data: CalculateShippingFeeType,
    user: AccessTokenPayload
  ): Promise<CalculateShippingFeeResType> {
    try {
      const {
        height,
        weight,
        length,
        width,
        service_type_id,
        service_id,
        insurance_value,
        coupon,
        cod_failed_amount,
        cod_value,
        cartItemId
      } = data

      const detectedAddresses = await this.detectUserAddresses(user, cartItemId)
      const from_district_id = detectedAddresses.fromDistrictId
      const from_ward_code = detectedAddresses.fromWardCode
      const to_district_id = detectedAddresses.toDistrictId
      const to_ward_code = detectedAddresses.toWardCode

      if (!to_district_id || to_district_id <= 0) {
        throw InvalidDistrictIdException
      }

      if (!to_ward_code) {
        throw MissingWardCodeException
      }

      if (height <= 0 || weight <= 0 || length <= 0 || width <= 0) {
        throw InvalidDimensionsException
      }

      if (!service_type_id && !service_id) {
        throw MissingServiceIdentifierException
      }

      const shipData = {
        to_district_id,
        to_ward_code,
        height,
        weight,
        length,
        width,
        service_type_id: service_type_id || undefined,
        service_id,
        from_district_id,
        from_ward_code,
        insurance_value: insurance_value || undefined,
        coupon: coupon || undefined,
        cod_failed_amount: cod_failed_amount || undefined,
        cod_value: cod_value || undefined,
        items: [
          {
            name: 'Package',
            quantity: 1,
            height,
            weight,
            length,
            width
          }
        ]
      }

      const response = await this.ghnService.calculateFee.calculateShippingFee(shipData)

      return {
        message: this.i18n.t('ship.success.CALCULATE_FEE_SUCCESS'),
        data: response
      }
    } catch (error) {
      this.handleGHNError(error, [
        InvalidDistrictIdException,
        MissingWardCodeException,
        InvalidDimensionsException,
        MissingServiceIdentifierException
      ])
    }
  }

  async calculateExpectedDeliveryTime(
    data: CalculateExpectedDeliveryTimeType,
    user: AccessTokenPayload
  ): Promise<CalculateExpectedDeliveryTimeResType> {
    try {
      const { service_id, cartItemId } = data

      const detectedAddresses = await this.detectUserAddresses(user, cartItemId)
      const from_district_id = detectedAddresses.fromDistrictId
      const from_ward_code = detectedAddresses.fromWardCode
      const to_district_id = detectedAddresses.toDistrictId
      const to_ward_code = detectedAddresses.toWardCode

      if (!service_id || service_id <= 0) {
        throw MissingServiceIdentifierException
      }

      if (!to_district_id || to_district_id <= 0) {
        throw InvalidDistrictIdException
      }

      if (!to_ward_code) {
        throw MissingWardCodeException
      }

      if (!from_district_id || from_district_id <= 0) {
        throw InvalidDistrictIdException
      }

      if (!from_ward_code) {
        throw MissingWardCodeException
      }

      const result = await this.ghnService.order.calculateExpectedDeliveryTime({
        service_id,
        to_district_id,
        to_ward_code,
        from_district_id,
        from_ward_code
      })

      return {
        message: this.i18n.t('ship.success.CALCULATE_DELIVERY_TIME_SUCCESS'),
        data: {
          leadtime: result.leadtime,
          order_date: result.order_date,
          expected_delivery_time: result.leadtime ? new Date(result.leadtime * 1000).toISOString() : undefined
        }
      }
    } catch (error) {
      this.handleGHNError(error, [
        MissingServiceIdentifierException,
        InvalidDistrictIdException,
        MissingWardCodeException
      ])
    }
  }

  async processOrderStatusUpdate(payload: GHNWebhookPayloadType): Promise<{ message: string }> {
    try {
      const orderCode = payload.OrderCode || payload.order_code
      const status = payload.Status || payload.status

      if (!orderCode || !status) {
        throw InvalidWebhookPayloadException
      }

      const shipping = await this.shippingRepo.findByOrderCode(orderCode)
      if (!shipping) {
        throw ShippingOrderNotFoundException
      }

      await this.shippingRepo.updateStatus(shipping.orderId, status as OrderShippingStatusType)

      await this.shippingRepo.updateOrderStatus(shipping.orderId, status as OrderShippingStatusType)

      return { message: 'OK' }
    } catch {
      return { message: 'ignored' }
    }
  }

  /**
   * Lấy thông tin chi tiết đơn hàng từ GHN
   */
  async getOrderInfo(query: GetOrderInfoQueryType): Promise<GetOrderInfoResType> {
    try {
      const { orderCode } = query

      if (!orderCode || orderCode.trim().length === 0) {
        throw new BadRequestException('Order code is required and cannot be empty')
      }

      // Kiểm tra đơn hàng có tồn tại trong hệ thống không
      const shipping = await this.shippingRepo.findByOrderCode(orderCode)
      if (!shipping) {
        throw ShippingOrderNotFoundException
      }

      // Kiểm tra trạng thái shipping - chỉ lấy thông tin khi đã tạo GHN order thành công
      if (shipping.status !== 'CREATED' || !shipping.orderCode) {
        throw new BadRequestException('Shipping order not ready - GHN order not created yet')
      }

      // Lấy thông tin order để validate
      const order = await this.sharedOrderRepo.getOrderWithShippingForGHN(shipping.orderId)
      if (!order) {
        throw new BadRequestException('Order not found')
      }

      // Gọi API GHN để lấy thông tin đơn hàng
      const orderInfo = await this.ghnService.order.orderInfo({ order_code: orderCode })

      if (!orderInfo) {
        throw new BadRequestException('No order information returned from GHN')
      }

      return {
        message: this.i18n.t('ship.success.GET_ORDER_INFO_SUCCESS'),
        data: orderInfo
      }
    } catch (error) {
      if (error === ShippingOrderNotFoundException || error instanceof BadRequestException) {
        throw error
      }

      if (error?.response?.status === 404) {
        throw new BadRequestException('Order not found in GHN system')
      }

      if (error?.response?.status === 401 || error?.response?.status === 403) {
        throw new BadRequestException('Unauthorized access to GHN API')
      }

      throw ShippingServiceUnavailableException
    }
  }

  /**
   * Lấy URL theo dõi đơn hàng từ GHN
   */
  async getTrackingUrl(query: GetTrackingUrlQueryType): Promise<GetTrackingUrlResType> {
    try {
      const { orderCode } = query

      if (!orderCode || orderCode.trim().length === 0) {
        throw new BadRequestException('Order code is required and cannot be empty')
      }

      // Kiểm tra đơn hàng có tồn tại trong hệ thống không
      const shipping = await this.shippingRepo.findByOrderCode(orderCode)
      if (!shipping) {
        throw ShippingOrderNotFoundException
      }

      // Kiểm tra trạng thái shipping - chỉ lấy tracking URL khi đã tạo GHN order thành công
      if (shipping.status !== 'CREATED' || !shipping.orderCode) {
        throw new BadRequestException('Shipping order not ready - GHN order not created yet')
      }

      // Gọi API GHN để lấy tracking URL
      const trackingUrl = await this.ghnService.order.getTrackingUrl(orderCode)

      if (!trackingUrl) {
        throw new BadRequestException('No tracking URL returned from GHN')
      }

      return {
        message: this.i18n.t('ship.success.GET_TRACKING_URL_SUCCESS'),
        data: {
          trackingUrl: trackingUrl.toString(),
          orderCode
        }
      }
    } catch (error) {
      // Log error cho debugging
      this.logger.error(`Failed to get tracking URL for orderCode: ${query.orderCode}`, error)

      if (error === ShippingOrderNotFoundException || error instanceof BadRequestException) {
        throw error
      }

      // Handle GHN API specific errors
      if (error?.response?.status === 404) {
        throw new BadRequestException('Order not found in GHN system')
      }

      if (error?.response?.status === 401 || error?.response?.status === 403) {
        throw new BadRequestException('Unauthorized access to GHN API')
      }

      throw ShippingServiceUnavailableException
    }
  }
}
