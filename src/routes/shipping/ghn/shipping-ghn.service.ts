import { Injectable, Inject, BadRequestException, Logger } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { Ghn } from 'giaohangnhanh'
import { SharedOrderRepository } from 'src/shared/repositories/shared-order.repo'
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

@Injectable()
export class ShippingService {
  private readonly logger = new Logger(ShippingService.name)

  constructor(
    private readonly i18n: I18nService,
    @Inject(GHN_CLIENT) private readonly ghnService: Ghn,
    private readonly shippingRepo: ShippingRepo,
    private readonly sharedOrderRepo: SharedOrderRepository
  ) {}

  /**
   * Lấy danh sách tỉnh/thành phố
   */
  async getProvinces(): Promise<GetProvincesResType> {
    try {
      const provinces = await this.ghnService.address.getProvinces()

      return {
        message: this.i18n.t('ship.success.GET_PROVINCES_SUCCESS'),
        data: provinces
      }
    } catch (error) {
      this.logger.error('Failed to get provinces from GHN:', error)
      throw ShippingServiceUnavailableException
    }
  }

  /**
   * Lấy danh sách quận/huyện theo tỉnh/thành phố
   */
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
      if (error === InvalidProvinceIdException) {
        throw error
      }

      this.logger.error(`Failed to get districts for province ${query.provinceId}:`, error)
      throw ShippingServiceUnavailableException
    }
  }

  /**
   * Lấy danh sách phường/xã theo quận/huyện
   */
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
      if (error === InvalidDistrictIdException) {
        throw error
      }

      this.logger.error(`Failed to get wards for district ${query.districtId}:`, error)
      throw ShippingServiceUnavailableException
    }
  }

  /**
   * Lấy danh sách dịch vụ vận chuyển có sẵn
   */
  async getServiceList(query: GetServiceListQueryType): Promise<GetServiceListResType> {
    try {
      const { fromDistrictId, toDistrictId } = query

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
      if (error === InvalidDistrictIdException) {
        throw error
      }

      this.logger.error(
        `Failed to get service list for districts ${query.fromDistrictId} -> ${query.toDistrictId}:`,
        error
      )
      throw ShippingServiceUnavailableException
    }
  }

  /**
   * Tính phí vận chuyển
   */
  async calculateShippingFee(data: CalculateShippingFeeType): Promise<CalculateShippingFeeResType> {
    try {
      const {
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
      } = data

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
      if (
        error === InvalidDistrictIdException ||
        error === MissingWardCodeException ||
        error === InvalidDimensionsException ||
        error === MissingServiceIdentifierException
      ) {
        throw error
      }

      this.logger.error('Failed to calculate shipping fee:', error)
      throw ShippingServiceUnavailableException
    }
  }

  /**
   * Tính thời gian giao hàng dự kiến
   */
  async calculateExpectedDeliveryTime(
    data: CalculateExpectedDeliveryTimeType
  ): Promise<CalculateExpectedDeliveryTimeResType> {
    try {
      const { service_id, to_district_id, to_ward_code, from_district_id, from_ward_code } = data

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
      if (
        error === MissingServiceIdentifierException ||
        error === InvalidDistrictIdException ||
        error === MissingWardCodeException
      ) {
        throw error
      }

      this.logger.error('Failed to calculate expected delivery time:', error)
      throw ShippingServiceUnavailableException
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

  /**
   * Transform GHN order info response cho frontend dễ sử dụng
   */
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
