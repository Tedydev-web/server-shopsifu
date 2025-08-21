import { Controller, Get, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { ShippingService } from './shipping.service'
import {
  GetProvincesResDTO,
  GetDistrictsResDTO,
  GetWardsResDTO,
  GetDistrictsQueryDTO,
  GetWardsQueryDTO
} from './shipping.dto'

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
}
