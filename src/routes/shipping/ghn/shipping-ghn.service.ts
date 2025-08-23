import { Injectable, Inject, BadRequestException, Logger } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { Ghn } from 'giaohangnhanh'
import { SharedOrderRepository } from 'src/shared/repositories/shared-order.repo'
import { SharedShippingRepository } from 'src/shared/repositories/shared-shipping.repo'
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
  GetOrderInfoResType
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
    private readonly sharedShippingRepo: SharedShippingRepository,
    private readonly prismaService: PrismaService
  ) {}

  /**
   * Auto-detect địa chỉ từ cartItemIds và user context
   */
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
      this.logger.log(`🔍 detectUserAddresses called with userId: ${user?.userId}, cartItemId:`, cartItemId)

      // User đã được validate bởi @ActiveUser() decorator
      this.logger.log(`🔍 User authenticated with userId: ${user.userId}`)

      // Lấy địa chỉ mặc định của user
      this.logger.log(`🔍 Looking for user default address for userId: ${user.userId}`)
      const userAddress = await this.prismaService.userAddress.findFirst({
        where: {
          userId: user.userId,
          isDefault: true
        },
        include: { address: true }
      })
      this.logger.log(`📍 User address found:`, userAddress?.address ? 'Yes' : 'No')

      if (!userAddress || !userAddress.address) {
        this.logger.error(`❌ User default address not found for userId: ${user.userId}`)
        throw new BadRequestException('User default address not found')
      }

      // Tìm shop address theo thứ tự ưu tiên
      this.logger.log(`🔍 Looking for shop address...`)
      const shopAddress = await this.findShopAddress(user.userId, cartItemId)
      this.logger.log(`📍 Shop address found:`, shopAddress ? 'Yes' : 'No')

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
      this.logger.log(`📍 Final detected addresses:`, result)
      return result
    } catch (error) {
      this.logger.error('Failed to detect user addresses:', error)
      throw error
    }
  }

  /**
   * Tìm shop address theo thứ tự ưu tiên
   */
  private async findShopAddress(userId: string, cartItemId?: string): Promise<any> {
    this.logger.log(`🔍 findShopAddress called with userId: ${userId}, cartItemId:`, cartItemId)
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
        this.logger.log(`🔍 Found shopId from cartItem: ${shopId}`)
        if (shopId) {
          this.logger.log(`🔍 Looking for shop address for shopId: ${shopId}`)
          const shopUserAddress = await this.prismaService.userAddress.findFirst({
            where: { userId: shopId, isDefault: true },
            include: { address: true }
          })
          this.logger.log(`📍 Shop address found for shopId ${shopId}:`, shopUserAddress?.address ? 'Yes' : 'No')
          if (shopUserAddress?.address) {
            this.logger.log(`✅ Returning shop address for shopId: ${shopId}`)
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
  private handleGHNError(error: any, context: string, specificExceptions: any[] = []): never {
    if (specificExceptions.includes(error)) {
      throw error
    }
    this.logger.error(`GHN API error in ${context}:`, error)
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
      this.handleGHNError(error, 'getProvinces')
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
      this.handleGHNError(error, 'getDistricts', [InvalidProvinceIdException])
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
      this.handleGHNError(error, 'getWards', [InvalidDistrictIdException])
    }
  }

  async getServiceList(query: GetServiceListQueryType, user: AccessTokenPayload): Promise<GetServiceListResType> {
    try {
      const { cartItemId } = query
      this.logger.log(`🔍 getServiceList called with cartItemId:`, cartItemId)

      // Auto-detection hoàn toàn từ cartItemId
      const detectedAddresses = await this.detectUserAddresses(user, cartItemId)
      this.logger.log(`📍 Detected addresses:`, detectedAddresses)
      const fromDistrictId = detectedAddresses.fromDistrictId
      const toDistrictId = detectedAddresses.toDistrictId

      this.logger.log(`🚚 GHN API params - fromDistrictId: ${fromDistrictId}, toDistrictId: ${toDistrictId}`)

      if (!fromDistrictId || fromDistrictId <= 0) {
        this.logger.error(`❌ Invalid fromDistrictId: ${fromDistrictId}`)
        throw InvalidDistrictIdException
      }

      if (!toDistrictId || toDistrictId <= 0) {
        this.logger.error(`❌ Invalid toDistrictId: ${toDistrictId}`)
        throw InvalidDistrictIdException
      }

      this.logger.log(
        `📡 Calling GHN API getServiceList with fromDistrictId: ${fromDistrictId}, toDistrictId: ${toDistrictId}`
      )
      const services = await this.ghnService.calculateFee.getServiceList(fromDistrictId, toDistrictId)
      this.logger.log(`✅ GHN API response received, services count:`, services?.length || 0)

      const normalized = services.map((s: any) => ({
        ...s,
        config_fee_id: s.config_fee_id === '' ? null : s.config_fee_id,
        extra_cost_id: s.extra_cost_id === '' ? null : s.extra_cost_id,
        standard_config_fee_id: s.standard_config_fee_id === '' ? null : s.standard_config_fee_id,
        standard_extra_cost_id: s.standard_extra_cost_id === '' ? null : s.standard_extra_cost_id
      }))

      this.logger.log(`🎯 Normalized services count:`, normalized.length)
      return {
        message: this.i18n.t('ship.success.GET_SERVICE_LIST_SUCCESS'),
        data: normalized
      }
    } catch (error) {
      this.logger.error(`💥 getServiceList error:`, error)
      this.handleGHNError(error, 'getServiceList', [InvalidDistrictIdException])
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

      // Auto-detection hoàn toàn từ cartItemId
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
        service_type_id,
        service_id,
        from_district_id,
        from_ward_code,
        insurance_value,
        coupon,
        cod_failed_amount,
        cod_value
      }

      const response = await this.ghnService.calculateFee.calculateShippingFee(shipData)

      return {
        message: this.i18n.t('ship.success.CALCULATE_FEE_SUCCESS'),
        data: response
      }
    } catch (error) {
      this.handleGHNError(error, 'calculateShippingFee', [
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

      // Auto-detection hoàn toàn từ cartItemId
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
      this.handleGHNError(error, 'calculateExpectedDeliveryTime', [
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

      // Transform GHN response để frontend dễ sử dụng hơn
      const transformedData = this.transformOrderInfoResponse(orderInfo)

      return {
        message: this.i18n.t('ship.success.GET_ORDER_INFO_SUCCESS'),
        data: transformedData
      }
    } catch (error) {
      // Log error cho debugging
      this.logger.error(`Failed to get order info for orderCode: ${query.orderCode}`, error)

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

  private transformOrderInfoResponse(ghnResponse: any): any {
    return {
      // Basic order info
      order_code: ghnResponse.order_code,
      client_order_code: ghnResponse.client_order_code,
      status: ghnResponse.status,

      // Dates (keep as-is, GHN handles string/Date conversion)
      created_date: ghnResponse.created_date,
      updated_date: ghnResponse.updated_date,
      order_date: ghnResponse.order_date,
      finish_date: ghnResponse.finish_date,
      leadtime: ghnResponse.leadtime,

      // From info (sender)
      from_name: ghnResponse.from_name,
      from_phone: ghnResponse.from_phone,
      from_address: ghnResponse.from_address,
      from_ward_code: ghnResponse.from_ward_code,
      from_district_id: ghnResponse.from_district_id,

      // To info (receiver)
      to_name: ghnResponse.to_name,
      to_phone: ghnResponse.to_phone,
      to_address: ghnResponse.to_address,
      to_ward_code: ghnResponse.to_ward_code,
      to_district_id: ghnResponse.to_district_id,

      // Package info
      weight: ghnResponse.weight,
      length: ghnResponse.length,
      width: ghnResponse.width,
      height: ghnResponse.height,
      converted_weight: ghnResponse.converted_weight,

      // Payment & fees
      cod_amount: ghnResponse.cod_amount,
      order_value: ghnResponse.order_value,
      insurance_value: ghnResponse.insurance_value,
      cod_collect_date: ghnResponse.cod_collect_date,
      cod_transfer_date: ghnResponse.cod_transfer_date,
      is_cod_collected: ghnResponse.is_cod_collected,
      is_cod_transferred: ghnResponse.is_cod_transferred,

      // Service info
      service_id: ghnResponse.service_id,
      service_type_id: ghnResponse.service_type_id,
      payment_type_id: ghnResponse.payment_type_id,

      // Notes & content
      content: ghnResponse.content,
      note: ghnResponse.note,
      required_note: ghnResponse.required_note,
      employee_note: ghnResponse.employee_note,
      coupon: ghnResponse.coupon,

      // Tracking & log (keep as raw unknown[] from GHN)
      log: ghnResponse.log || [],
      tag: ghnResponse.tag || [],

      // Warehouse info
      pick_warehouse_id: ghnResponse.pick_warehouse_id,
      deliver_warehouse_id: ghnResponse.deliver_warehouse_id,
      current_warehouse_id: ghnResponse.current_warehouse_id,
      return_warehouse_id: ghnResponse.return_warehouse_id,
      next_warehouse_id: ghnResponse.next_warehouse_id,

      // Additional useful fields
      soc_id: ghnResponse.soc_id,
      version_no: ghnResponse.version_no,
      updated_source: ghnResponse.updated_source,
      updated_employee: ghnResponse.updated_employee,
      updated_client: ghnResponse.updated_client,

      // Return info
      return_name: ghnResponse.return_name,
      return_phone: ghnResponse.return_phone,
      return_address: ghnResponse.return_address,

      // Internal ID
      _id: ghnResponse._id
    }
  }
}
