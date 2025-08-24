import { Injectable, Inject, Logger } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { Ghn } from 'giaohangnhanh'
import { ConfigService } from '@nestjs/config'
import { SharedOrderRepository } from 'src/shared/repositories/shared-order.repo'
import { PrismaService } from 'src/shared/services/prisma.service'
import { ShippingProducer } from 'src/shared/queue/producer/shipping.producer'
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
  ShippingOrderNotFoundException,
  UserAddressNotFoundException,
  ShopAddressNotFoundException,
  OrderCodeRequiredException,
  ShippingOrderNotReadyException,
  OrderNotFoundException,
  NoOrderInfoFromGHNException,
  NoTrackingUrlFromGHNException
} from './shipping-ghn.error'
import { GHN_CLIENT } from 'src/shared/constants/shipping.constants'
import { ShippingRepo } from './shipping-ghn.repo'

import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Injectable()
export class ShippingService {
  private readonly logger = new Logger(ShippingService.name)

  constructor(
    private readonly i18n: I18nService,
    @Inject(GHN_CLIENT) private readonly ghnService: Ghn,
    private readonly configService: ConfigService,
    private readonly shippingRepo: ShippingRepo,
    private readonly sharedOrderRepo: SharedOrderRepository,
    private readonly prismaService: PrismaService,
    private readonly shippingProducer: ShippingProducer
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
    const [userAddress, shopAddress] = await Promise.all([
      this.prismaService.userAddress.findFirst({
        where: { userId: user.userId, isDefault: true },
        include: { address: true }
      }),
      this.findShopAddress(user.userId, cartItemId)
    ])

    if (!userAddress?.address) {
      throw UserAddressNotFoundException
    }

    if (!shopAddress?.address) {
      throw ShopAddressNotFoundException
    }

    return {
      fromDistrictId: shopAddress.address.districtId || 0,
      fromWardCode: shopAddress.address.wardCode || '',
      toDistrictId: userAddress.address.districtId || 0,
      toWardCode: userAddress.address.wardCode || ''
    }
  }

  private async findShopAddress(
    userId: string,
    cartItemId?: string
  ): Promise<{ address: { districtId: number | null; wardCode: string | null } } | null> {
    if (!cartItemId) return null

    const cartItem = await this.prismaService.cartItem.findFirst({
      where: { id: cartItemId, userId },
      include: {
        sku: {
          include: {
            product: { select: { createdById: true } }
          }
        }
      }
    })

    const shopId = cartItem?.sku?.product?.createdById
    if (!shopId) return null

    const shopUserAddress = await this.prismaService.userAddress.findFirst({
      where: { userId: shopId, isDefault: true },
      include: { address: true }
    })

    return shopUserAddress?.address ? { address: shopUserAddress.address } : null
  }

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
    } catch {
      throw ShippingServiceUnavailableException
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
    } catch {
      throw ShippingServiceUnavailableException
    }
  }

  async getServiceList(query: GetServiceListQueryType, user: AccessTokenPayload): Promise<GetServiceListResType> {
    try {
      const { cartItemId } = query
      const { fromDistrictId, toDistrictId } = await this.detectUserAddresses(user, cartItemId)

      if (!fromDistrictId || fromDistrictId <= 0 || !toDistrictId || toDistrictId <= 0) {
        throw InvalidDistrictIdException
      }

      const services = await this.ghnService.calculateFee.getServiceList(fromDistrictId, toDistrictId)

      return {
        message: this.i18n.t('ship.success.GET_SERVICE_LIST_SUCCESS'),
        data: services
      }
    } catch (error) {
      if (
        error === InvalidDistrictIdException ||
        error === UserAddressNotFoundException ||
        error === ShopAddressNotFoundException
      ) {
        throw error
      }
      throw ShippingServiceUnavailableException
    }
  }

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

      const shopId = this.configService.getOrThrow<number>('GHN_SHOP_ID')

      const { fromDistrictId, fromWardCode, toDistrictId, toWardCode } = await this.detectUserAddresses(
        user,
        cartItemId
      )

      if (!toDistrictId || toDistrictId <= 0 || !toWardCode) {
        throw !toDistrictId || toDistrictId <= 0 ? InvalidDistrictIdException : MissingWardCodeException
      }

      if (height <= 0 || weight <= 0 || length <= 0 || width <= 0) {
        throw InvalidDimensionsException
      }

      if (!service_type_id && !service_id) {
        throw MissingServiceIdentifierException
      }

      const shipData = {
        ShopID: shopId,
        to_district_id: toDistrictId,
        to_ward_code: toWardCode,
        height,
        weight,
        length,
        width,
        service_type_id,
        service_id,
        from_district_id: fromDistrictId,
        from_ward_code: fromWardCode,
        insurance_value: insurance_value || undefined,
        coupon: coupon || undefined,
        cod_failed_amount: cod_failed_amount || undefined,
        cod_value: cod_value || undefined,
        items: [{ name: 'Package', quantity: 1, height, weight, length, width }]
      }

      const response = await this.ghnService.calculateFee.calculateShippingFee(shipData)

      return {
        message: this.i18n.t('ship.success.CALCULATE_FEE_SUCCESS'),
        data: response
      }
    } catch (error) {
      if (
        [
          InvalidDistrictIdException,
          MissingWardCodeException,
          InvalidDimensionsException,
          MissingServiceIdentifierException,
          UserAddressNotFoundException,
          ShopAddressNotFoundException
        ].includes(error)
      ) {
        throw error
      }
      throw ShippingServiceUnavailableException
    }
  }

  async calculateExpectedDeliveryTime(
    data: CalculateExpectedDeliveryTimeType,
    user: AccessTokenPayload
  ): Promise<CalculateExpectedDeliveryTimeResType> {
    try {
      const { service_id, cartItemId } = data

      if (!service_id || service_id <= 0) {
        throw MissingServiceIdentifierException
      }

      const { fromDistrictId, fromWardCode, toDistrictId, toWardCode } = await this.detectUserAddresses(
        user,
        cartItemId
      )

      if (
        !toDistrictId ||
        toDistrictId <= 0 ||
        !toWardCode ||
        !fromDistrictId ||
        fromDistrictId <= 0 ||
        !fromWardCode
      ) {
        throw InvalidDistrictIdException
      }

      const result = await this.ghnService.order.calculateExpectedDeliveryTime({
        service_id,
        to_district_id: toDistrictId,
        to_ward_code: toWardCode,
        from_district_id: fromDistrictId,
        from_ward_code: fromWardCode
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
        [
          MissingServiceIdentifierException,
          InvalidDistrictIdException,
          MissingWardCodeException,
          UserAddressNotFoundException,
          ShopAddressNotFoundException
        ].includes(error)
      ) {
        throw error
      }
      throw ShippingServiceUnavailableException
    }
  }

  async processOrderStatusUpdate(
    payload: GHNWebhookPayloadType
  ): Promise<{ message: string; code: number; timestamp: string; orderCode?: string; status?: string }> {
    try {
      const orderCode = payload.orderCode
      const status = payload.status

      if (!orderCode) {
        return {
          message: 'Webhook ignored: Missing orderCode',
          code: 400,
          timestamp: new Date().toISOString()
        }
      }

      if (!status) {
        return {
          message: 'Webhook ignored: Missing status',
          code: 400,
          timestamp: new Date().toISOString()
        }
      }

      await this.shippingProducer.enqueueWebhookProcessing(payload)

      return {
        message: this.i18n.t('ship.WEBHOOK_PROCESSED_SUCCESS'),
        code: 200,
        timestamp: new Date().toISOString(),
        orderCode,
        status
      }
    } catch {
      return {
        message: this.i18n.t('ship.WEBHOOK_PROCESSING_FAILED'),
        code: 200,
        timestamp: new Date().toISOString()
      }
    }
  }

  async getOrderInfo(query: GetOrderInfoQueryType): Promise<GetOrderInfoResType> {
    try {
      const { orderCode } = query

      if (!orderCode?.trim()) {
        throw OrderCodeRequiredException
      }

      const shipping = await this.shippingRepo.findByOrderCode(orderCode)
      if (!shipping) {
        throw ShippingOrderNotFoundException
      }

      if (shipping.status !== 'CREATED' || !shipping.orderCode) {
        throw ShippingOrderNotReadyException
      }

      const order = await this.sharedOrderRepo.getOrderWithShippingForGHN(shipping.orderId)

      if (!order) {
        throw OrderNotFoundException
      }

      const orderInfo = await this.ghnService.order.orderInfo({ order_code: orderCode })

      if (!orderInfo) {
        throw NoOrderInfoFromGHNException
      }

      return {
        message: this.i18n.t('ship.success.GET_ORDER_INFO_SUCCESS'),
        data: orderInfo
      }
    } catch (error) {
      if (
        [
          ShippingOrderNotFoundException,
          OrderCodeRequiredException,
          ShippingOrderNotReadyException,
          OrderNotFoundException,
          NoOrderInfoFromGHNException
        ].includes(error)
      ) {
        throw error
      }
      throw ShippingServiceUnavailableException
    }
  }

  async getTrackingUrl(query: GetTrackingUrlQueryType): Promise<GetTrackingUrlResType> {
    try {
      const { orderCode } = query

      if (!orderCode?.trim()) {
        throw OrderCodeRequiredException
      }

      const shipping = await this.shippingRepo.findByOrderCode(orderCode)
      if (!shipping) {
        throw ShippingOrderNotFoundException
      }

      if (shipping.status !== 'CREATED' || !shipping.orderCode) {
        throw ShippingOrderNotReadyException
      }

      const trackingUrl = await this.ghnService.order.getTrackingUrl(orderCode)

      if (!trackingUrl) {
        throw NoTrackingUrlFromGHNException
      }

      return {
        message: this.i18n.t('ship.success.GET_TRACKING_URL_SUCCESS'),
        data: {
          trackingUrl: trackingUrl.toString(),
          orderCode
        }
      }
    } catch (error) {
      if (
        [
          ShippingOrderNotFoundException,
          OrderCodeRequiredException,
          ShippingOrderNotReadyException,
          NoTrackingUrlFromGHNException
        ].includes(error)
      ) {
        throw error
      }
      throw ShippingServiceUnavailableException
    }
  }

  /**
   * Hủy đơn hàng GHN
   * @param orderCode Mã đơn hàng GHN cần hủy
   * @returns Kết quả hủy đơn hàng
   */
  async cancelGHNOrder(orderCode: string): Promise<{ success: boolean; message: string }> {
    try {
      this.logger.log(`[GHN_SERVICE] Bắt đầu hủy đơn hàng GHN: ${orderCode}`)

      if (!orderCode?.trim()) {
        throw new Error('Order code is required')
      }

      // Gọi GHN API để hủy đơn hàng
      const result = await this.ghnService.order.cancelOrder({
        orderCodes: [orderCode]
      })

      this.logger.log(`[GHN_SERVICE] Kết quả hủy đơn hàng GHN: ${JSON.stringify(result, null, 2)}`)

      // Kiểm tra kết quả từ GHN
      if (result && Array.isArray(result)) {
        const orderResult = result.find((item: any) => item.order_code === orderCode)
        if (orderResult && orderResult.result === true) {
          return {
            success: true,
            message: `Hủy đơn hàng GHN thành công: ${orderCode}`
          }
        }
      }

      return {
        success: false,
        message: `Không thể hủy đơn hàng GHN: ${orderCode}`
      }
    } catch (error) {
      this.logger.error(`[GHN_SERVICE] Lỗi khi hủy đơn hàng GHN: ${error.message}`)
      return {
        success: false,
        message: `Lỗi khi hủy đơn hàng GHN: ${error.message}`
      }
    }
  }
}
