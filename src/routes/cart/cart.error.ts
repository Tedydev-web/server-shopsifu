import { BadRequestException, NotFoundException } from '@nestjs/common'

export const NotFoundSKUException = new NotFoundException('cart.error.SKU_NOT_FOUND')

export const OutOfStockSKUException = new BadRequestException('cart.error.OUT_OF_STOCK_SKU')

export const ProductNotFoundException = new NotFoundException('cart.error.PRODUCT_NOT_FOUND')
