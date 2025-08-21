import { Injectable, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
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
  CalculateShippingFeeType
} from './shipping.model'
import {
  ShippingServiceUnavailableException,
  InvalidProvinceIdException,
  InvalidDistrictIdException,
  MissingWardCodeException,
  InvalidDimensionsException,
  MissingServiceIdentifierException
} from './shipping.error'
import { GHN_CLIENT } from '../../shared/constants/shipping.constants'

@Injectable()
export class ShippingService {
  private readonly ghnService: Ghn

  constructor(
    private readonly configService: ConfigService,
    private readonly i18n: I18nService<I18nTranslations>,
    @Inject(GHN_CLIENT) ghnClient: Ghn
  ) {
    this.ghnService = ghnClient
  }

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

      return {
        message: this.i18n.t('ship.success.GET_SERVICE_LIST_SUCCESS'),
        data: services
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
}
