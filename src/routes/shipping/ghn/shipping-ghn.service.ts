import { Injectable, Inject } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { Ghn } from 'giaohangnhanh'
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
  GHNWebhookPayloadType
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
  constructor(
    private readonly i18n: I18nService<I18nTranslations>,
    @Inject(GHN_CLIENT) private readonly ghnService: Ghn,
    private readonly shippingRepo: ShippingRepo
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
    } catch {
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

      const feeData = response

      return {
        message: this.i18n.t('ship.success.CALCULATE_FEE_SUCCESS'),
        data: feeData
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

      throw ShippingServiceUnavailableException
    }
  }

  // =============== Order Features (Phase 1) ===============
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
}
