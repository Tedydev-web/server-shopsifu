import { BadRequestException, NotFoundException } from '@nestjs/common'

export const OrderNotFoundException = new NotFoundException('Error.OrderNotFound')
export const ProductNotFoundException = new NotFoundException('Error.ProductNotFound')
export const OutOfStockSKUException = new BadRequestException('Error.OutOfStockSKU')
export const NotFoundCartItemException = new NotFoundException('Error.NotFoundCartItem')
export const SKUNotBelongToShopException = new BadRequestException('Error.SKUNotBelongToShop')
export const CannotCancelOrderException = new BadRequestException('Error.CannotCancelOrder')
