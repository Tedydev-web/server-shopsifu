import { BadRequestException, InternalServerErrorException } from '@nestjs/common'

export const ShippingServiceUnavailableException = new InternalServerErrorException([
  {
    message: 'Error.ShippingServiceUnavailable',
    path: 'shipping'
  }
])

export const InvalidProvinceIdException = new BadRequestException([
  {
    message: 'Error.InvalidProvinceId',
    path: 'provinceId'
  }
])

export const InvalidDistrictIdException = new BadRequestException([
  {
    message: 'Error.InvalidDistrictId',
    path: 'districtId'
  }
])

export const InvalidWardCodeException = new BadRequestException([
  {
    message: 'Error.InvalidWardCode',
    path: 'wardCode'
  }
])
