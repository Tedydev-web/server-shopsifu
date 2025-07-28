import { BadRequestException, NotFoundException } from '@nestjs/common'

export const VNPayPaymentNotFoundException = new NotFoundException('Error.VNPayPaymentNotFound')
export const VNPayInvalidAmountException = new BadRequestException('Error.VNPayInvalidAmount')
export const VNPayOrderAlreadyConfirmedException = new BadRequestException('Error.VNPayOrderAlreadyConfirmed')
export const VNPayDataIntegrityException = new BadRequestException('Error.VNPayDataIntegrityFailed')
export const VNPayPaymentFailedException = new BadRequestException('Error.VNPayPaymentFailed')
export const VNPayInvalidDataException = new BadRequestException('Error.VNPayInvalidData')
