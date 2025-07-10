import { BadRequestException, NotFoundException } from '@nestjs/common'

export const NotFoundSKUException = new NotFoundException('cart.cart.error.SKU_NOT_FOUND')

export const OutOfStockSKUException = new BadRequestException('cart.cart.error.SKU_OUT_OF_STOCK')

export const ProductNotFoundException = new NotFoundException('cart.cart.error.PRODUCT_NOT_FOUND')

export const NotFoundCartItemException = new NotFoundException('cart.cart.error.CART_ITEM_NOT_FOUND')

export const InvalidQuantityException = new BadRequestException('cart.cart.error.INVALID_QUANTITY')
