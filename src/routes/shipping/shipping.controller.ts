import { Controller, Get, Query, Post, Body } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { ShippingService } from './shipping.service'
import {
  GetProvincesResDTO,
  GetDistrictsResDTO,
  GetWardsResDTO,
  GetServiceListResDTO,
  CalculateShippingFeeResDTO,
  CalculateExpectedDeliveryTimeDTO,
  CalculateExpectedDeliveryTimeResDTO,
  CreateOrderDTO,
  CreateOrderResDTO
} from './shipping.dto'
import { GetDistrictsQueryDTO, GetWardsQueryDTO, GetServiceListQueryDTO, CalculateShippingFeeDTO } from './shipping.dto'

@Controller('shipping')
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
  @IsPublic()
  @ZodSerializerDto(GetServiceListResDTO)
  getServiceList(@Query() query: GetServiceListQueryDTO) {
    return this.shippingService.getServiceList(query)
  }

  @Post('calculate-fee')
  @IsPublic()
  @ZodSerializerDto(CalculateShippingFeeResDTO)
  calculateShippingFee(@Body() data: CalculateShippingFeeDTO) {
    return this.shippingService.calculateShippingFee(data)
  }

  @Post('delivery-time')
  @IsPublic()
  @ZodSerializerDto(CalculateExpectedDeliveryTimeResDTO)
  calculateExpectedDeliveryTime(@Body() data: CalculateExpectedDeliveryTimeDTO) {
    return this.shippingService.calculateExpectedDeliveryTime(data)
  }

  @Post('create-order')
  @IsPublic()
  @ZodSerializerDto(CreateOrderResDTO)
  createOrder(@Body() data: CreateOrderDTO) {
    return this.shippingService.createOrder(data)
  }
}
