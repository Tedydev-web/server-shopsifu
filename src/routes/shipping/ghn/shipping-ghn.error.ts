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

export const UserAddressNotFoundException = new BadRequestException([
  {
    message: 'shipping.error.USER_ADDRESS_NOT_FOUND',
    path: 'userAddress'
  }
])

export const ShopAddressNotFoundException = new BadRequestException([
  {
    message: 'shipping.error.SHOP_ADDRESS_NOT_FOUND',
    path: 'shopAddress'
  }
])

export const OrderCodeRequiredException = new BadRequestException([
  {
    message: 'shipping.error.ORDER_CODE_REQUIRED',
    path: 'orderCode'
  }
])

export const ShippingOrderNotReadyException = new BadRequestException([
  {
    message: 'shipping.error.SHIPPING_ORDER_NOT_READY',
    path: 'shipping'
  }
])

export const OrderNotFoundException = new BadRequestException([
  {
    message: 'shipping.error.ORDER_NOT_FOUND',
    path: 'order'
  }
])

export const NoOrderInfoFromGHNException = new BadRequestException([
  {
    message: 'shipping.error.NO_ORDER_INFO_FROM_GHN',
    path: 'ghn'
  }
])

export const NoTrackingUrlFromGHNException = new BadRequestException([
  {
    message: 'shipping.error.NO_TRACKING_URL_FROM_GHN',
    path: 'ghn'
  }
])
