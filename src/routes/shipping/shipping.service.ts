import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { Ghn } from 'giaohangnhanh'
import {
  GetProvincesResType,
  GetDistrictsResType,
  GetWardsResType,
  GetDistrictsQueryType,
  GetWardsQueryType
} from './shipping.model'
import {
  ShippingServiceUnavailableException,
  InvalidProvinceIdException,
  InvalidDistrictIdException
} from './shipping.error'

@Injectable()
export class ShippingService {
  private readonly ghnService: Ghn

  constructor(
    private readonly configService: ConfigService,
    private readonly i18n: I18nService<I18nTranslations>
  ) {
    // Khởi tạo GHN service với config từ environment
    const token = this.configService.get<string>('GHN_TOKEN')
    const shopId = this.configService.get<number>('GHN_SHOP_ID')
    const host = this.configService.get<string>('GHN_HOST')
    const testMode = this.configService.get<boolean>('GHN_TEST_MODE') ?? true

    // Validate required config
    if (!token) {
      throw new Error('GHN_TOKEN is required in environment variables')
    }
    if (!shopId) {
      throw new Error('GHN_SHOP_ID is required in environment variables')
    }
    if (!host) {
      throw new Error('GHN_HOST is required in environment variables')
    }

    this.ghnService = new Ghn({
      token,
      shopId,
      host,
      testMode
    })
  }

  /**
   * Lấy danh sách tỉnh/thành phố
   */
  async getProvinces(): Promise<GetProvincesResType> {
    try {
      const provinces = await this.ghnService.address.getProvinces()

      return {
        message: 'Lấy danh sách tỉnh/thành phố thành công',
        data: provinces
      }
    } catch (error) {
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
        message: 'Lấy danh sách quận/huyện thành công',
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
        message: 'Lấy danh sách phường/xã thành công',
        data: wards
      }
    } catch (error) {
      if (error === InvalidDistrictIdException) {
        throw error
      }

      throw ShippingServiceUnavailableException
    }
  }
}
