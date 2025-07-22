import { NotFoundException, BadRequestException, ForbiddenException } from '@nestjs/common'

export const DiscountNotFoundException = new NotFoundException('discount.discount.error.NOT_FOUND')
export const DiscountCodeAlreadyExistsException = new BadRequestException('discount.discount.error.CODE_EXISTS')
export const DiscountForbiddenException = new ForbiddenException('discount.discount.error.FORBIDDEN')
