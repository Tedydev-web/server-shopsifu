import { BadRequestException, NotFoundException } from '@nestjs/common'

export const OrderNotFoundException = new NotFoundException(
	'order.order.error.NOT_FOUND'
)
export const ProductNotFoundException = new NotFoundException(
	'order.order.error.PRODUCT_NOT_FOUND'
)
export const OutOfStockSKUException = new BadRequestException(
	'order.order.error.OUT_OF_STOCK_SKU'
)
export const NotFoundCartItemException = new NotFoundException(
	'order.order.error.NOT_FOUND_CART_ITEM'
)
export const SKUNotBelongToShopException = new BadRequestException(
	'order.order.error.SKU_NOT_BELONG_TO_SHOP'
)
export const CannotCancelOrderException = new BadRequestException(
	'order.order.error.CANNOT_CANCEL'
)
