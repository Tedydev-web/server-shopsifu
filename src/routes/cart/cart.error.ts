import { BadRequestException, NotFoundException } from '@nestjs/common'

export const NotFoundSKUException = new NotFoundException('cart.error.SKU.NotFound')

export const OutOfStockSKUException = new BadRequestException('cart.error.SKU.OutOfStock')

export const ProductNotFoundException = new NotFoundException('cart.error.Product.NotFound')

export const NotFoundCartItemException = new NotFoundException('cart.error.CartItem.NotFound')

export const InvalidQuantityException = new BadRequestException('cart.error.CartItem.InvalidQuantity')
