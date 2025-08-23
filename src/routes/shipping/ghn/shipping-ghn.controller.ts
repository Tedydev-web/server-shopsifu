import { Controller, Get, Query, Post, Body } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { ShippingService } from './shipping-ghn.service'
import {
  GetProvincesResDTO,
  GetDistrictsResDTO,
  GetWardsResDTO,
  GetServiceListResDTO,
  CalculateShippingFeeResDTO,
  CalculateExpectedDeliveryTimeDTO,
  CalculateExpectedDeliveryTimeResDTO,
  GHNWebhookPayloadDTO,
  GHNWebhookResponseDTO,
  GetOrderInfoQueryDTO,
  GetOrderInfoResDTO,
  GetTrackingUrlQueryDTO,
  GetTrackingUrlResDTO
} from './shipping-ghn.dto'
import {
  GetDistrictsQueryDTO,
  GetWardsQueryDTO,
  GetServiceListQueryDTO,
  CalculateShippingFeeDTO
} from './shipping-ghn.dto'

@Controller('shipping/ghn')
export class ShippingController {
  constructor(private readonly shippingService: ShippingService) {}

  @Get('address/provinces')
  @IsPublic()
  @ZodSerializerDto(GetProvincesResDTO)
  getProvinces() {
    return this.shippingService.getProvinces()
  }

  @Get('address/districts')
  @IsPublic()
  @ZodSerializerDto(GetDistrictsResDTO)
  getDistricts(@Query() query: GetDistrictsQueryDTO) {
    return this.shippingService.getDistricts(query)
  }

  @Get('address/wards')
  @IsPublic()
  @ZodSerializerDto(GetWardsResDTO)
  getWards(@Query() query: GetWardsQueryDTO) {
    return this.shippingService.getWards(query)
  }

  @Get('services')
  @ZodSerializerDto(GetServiceListResDTO)
  getServiceList(@Query() query: GetServiceListQueryDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.shippingService.getServiceList(query, user)
  }

  @Post('calculate-fee')
  @ZodSerializerDto(CalculateShippingFeeResDTO)
  calculateShippingFee(@Body() data: CalculateShippingFeeDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.shippingService.calculateShippingFee(data, user)
  }

  @Post('delivery-time')
  @ZodSerializerDto(CalculateExpectedDeliveryTimeResDTO)
  calculateExpectedDeliveryTime(
    @Body() data: CalculateExpectedDeliveryTimeDTO,
    @ActiveUser() user: AccessTokenPayload
  ) {
    return this.shippingService.calculateExpectedDeliveryTime(data, user)
  }

  @Post('webhook/order-status')
  @IsPublic()
  @ZodSerializerDto(GHNWebhookResponseDTO)
  async ghnOrderStatus(@Body() body: GHNWebhookPayloadDTO) {
    return this.shippingService.processOrderStatusUpdate(body)
  }

  @Get('order-info')
  @ZodSerializerDto(GetOrderInfoResDTO)
  getOrderInfo(@Query() query: GetOrderInfoQueryDTO) {
    return this.shippingService.getOrderInfo(query)
  }

  @Get('tracking-url')
  @ZodSerializerDto(GetTrackingUrlResDTO)
  getTrackingUrl(@Query() query: GetTrackingUrlQueryDTO) {
    return this.shippingService.getTrackingUrl(query)
  }
}
