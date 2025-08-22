import {
  BadRequestException,
  InternalServerErrorException,
  NotFoundException,
  ServiceUnavailableException
} from '@nestjs/common'

export const ShippingServiceUnavailableException = new ServiceUnavailableException([
  {
    message: 'shipping.error.SERVICE_UNAVAILABLE',
    path: 'shipping'
  }
])

export const InvalidProvinceIdException = new BadRequestException([
  {
    message: 'shipping.error.INVALID_PROVINCE_ID',
    path: 'provinceId'
  }
])

export const InvalidDistrictIdException = new BadRequestException([
  {
    message: 'shipping.error.INVALID_DISTRICT_ID',
    path: 'districtId'
  }
])

export const InvalidWardCodeException = new BadRequestException([
  {
    message: 'shipping.error.INVALID_WARD_CODE',
    path: 'wardCode'
  }
])

export const MissingWardCodeException = new BadRequestException([
  {
    message: 'shipping.error.MISSING_WARD_CODE',
    path: 'wardCode'
  }
])

export const InvalidDimensionsException = new BadRequestException([
  {
    message: 'shipping.error.INVALID_DIMENSIONS',
    path: 'dimensions'
  }
])

export const MissingServiceIdentifierException = new BadRequestException([
  {
    message: 'shipping.error.MISSING_SERVICE_IDENTIFIER',
    path: 'service'
  }
])

export const ShippingOrderNotFoundException = new NotFoundException([
  {
    message: 'shipping.error.ORDER_NOT_FOUND',
    path: 'orderCode'
  }
])

export const InvalidWebhookPayloadException = new BadRequestException([
  {
    message: 'shipping.error.INVALID_WEBHOOK_PAYLOAD',
    path: 'webhook'
  }
])

export const ShippingOrderCreationFailedException = new InternalServerErrorException([
  {
    message: 'shipping.error.ORDER_CREATION_FAILED',
    path: 'shipping'
  }
])
