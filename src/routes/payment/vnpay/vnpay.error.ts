import { UnprocessableEntityException, BadRequestException, InternalServerErrorException } from '@nestjs/common'

export const VNPayInvalidChecksumException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_CHECKSUM', path: 'secureHash' }
])

export const VNPayDuplicateRequestException = new BadRequestException('payment.vnpay.error.VNPAY_DUPLICATE_REQUEST')

export const VNPayRefundAlreadyProcessedException = new BadRequestException(
  'payment.vnpay.error.VNPAY_REFUND_ALREADY_PROCESSED'
)

export const VNPayTransactionNotFoundException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_TRANSACTION_NOT_FOUND', path: 'orderId' }
])

export const VNPayServiceUnavailableException = new InternalServerErrorException(
  'payment.vnpay.error.VNPAY_SERVICE_UNAVAILABLE'
)
