import { ExceptionFactory } from 'src/shared/error'

// --- Cart-specific Exceptions sử dụng ExceptionFactory ---
export const NotFoundSKUException = ExceptionFactory.notFound('cart.error.SKU_NOT_FOUND', 'skuId')

export const OutOfStockSKUException = ExceptionFactory.outOfStock('cart.error.OUT_OF_STOCK', 'skuId')

export const ProductNotFoundException = ExceptionFactory.notFound('cart.error.PRODUCT_NOT_FOUND', 'productId')
