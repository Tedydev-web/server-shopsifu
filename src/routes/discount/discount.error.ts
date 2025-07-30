import { UnprocessableEntityException, NotFoundException, BadRequestException } from '@nestjs/common'

export const DiscountNotFoundException = new NotFoundException([
  {
    path: 'discountId',
    message: 'Error.DiscountNotFound'
  }
])

export const DiscountAlreadyExistsException = new UnprocessableEntityException([
  {
    path: 'code',
    message: 'Error.DiscountCodeAlreadyExists'
  }
])

export const DiscountExpiredException = new BadRequestException([
  {
    path: 'discountId',
    message: 'Error.DiscountExpired'
  }
])

export const DiscountUsageLimitExceededException = new BadRequestException([
  {
    path: 'discountId',
    message: 'Error.DiscountUsageLimitExceeded'
  }
])

export const DiscountMinOrderValueNotMetException = new BadRequestException([
  {
    path: 'orderTotal',
    message: 'Error.DiscountMinOrderValueNotMet'
  }
])

export const DiscountNotApplicableException = new BadRequestException([
  {
    path: 'discountId',
    message: 'Error.DiscountNotApplicable'
  }
])

export const DiscountCodeInvalidException = new BadRequestException([
  {
    path: 'code',
    message: 'Error.DiscountCodeInvalid'
  }
])
