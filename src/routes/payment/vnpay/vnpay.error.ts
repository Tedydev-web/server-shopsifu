import { UnprocessableEntityException, BadRequestException, InternalServerErrorException } from '@nestjs/common'

// ================== VNPay payment related errors ==================

export const VNPayInvalidChecksumException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_CHECKSUM', path: 'secureHash' }
])

export const VNPayInvalidAmountException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_AMOUNT', path: 'amount' }
])

export const VNPayInvalidOrderIdException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_ORDER_ID', path: 'orderId' }
])

export const VNPayInvalidTransactionException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_TRANSACTION', path: 'transactionNo' }
])

export const VNPayDuplicateRequestException = new BadRequestException('payment.vnpay.error.VNPAY_DUPLICATE_REQUEST')

export const VNPayRefundAlreadyProcessedException = new BadRequestException(
  'payment.vnpay.error.VNPAY_REFUND_ALREADY_PROCESSED'
)

export const VNPayTransactionNotFoundException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_TRANSACTION_NOT_FOUND', path: 'orderId' }
])

export const VNPayInvalidBankCodeException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_BANK_CODE', path: 'bankCode' }
])

export const VNPayInvalidCurrencyException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_CURRENCY', path: 'currency' }
])

export const VNPayInvalidLocaleException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_LOCALE', path: 'locale' }
])

export const VNPayInvalidOrderTypeException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_ORDER_TYPE', path: 'orderType' }
])

export const VNPayInvalidIpAddressException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_IP_ADDRESS', path: 'ipAddr' }
])

export const VNPayInvalidReturnUrlException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_RETURN_URL', path: 'returnUrl' }
])

export const VNPayInvalidIpnUrlException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_IPN_URL', path: 'ipnUrl' }
])

export const VNPayInvalidTransactionDateException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_TRANSACTION_DATE', path: 'transactionDate' }
])

export const VNPayInvalidCreateDateException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_CREATE_DATE', path: 'createDate' }
])

export const VNPayInvalidRequestIdException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_REQUEST_ID', path: 'requestId' }
])

export const VNPayInvalidTransactionTypeException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_TRANSACTION_TYPE', path: 'transactionType' }
])

export const VNPayInvalidCreateByException = new UnprocessableEntityException([
  { message: 'payment.vnpay.error.VNPAY_INVALID_CREATE_BY', path: 'createBy' }
])

export const VNPayServiceUnavailableException = new InternalServerErrorException(
  'payment.vnpay.error.VNPAY_SERVICE_UNAVAILABLE'
)
export const VNPayTimeoutException = new InternalServerErrorException('payment.vnpay.error.VNPAY_TIMEOUT')
export const VNPayNetworkErrorException = new InternalServerErrorException('payment.vnpay.error.VNPAY_NETWORK_ERROR')
