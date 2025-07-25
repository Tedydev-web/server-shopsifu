import { UnprocessableEntityException, NotFoundException, ForbiddenException } from '@nestjs/common'

// Discount code đã tồn tại
export const DiscountCodeAlreadyExistsException = new UnprocessableEntityException([
  {
    message: 'Error.DiscountCodeAlreadyExists',
    path: 'code'
  }
])

// Không tìm thấy discount
export const DiscountNotFoundException = new NotFoundException([
  {
    message: 'Error.DiscountNotFound',
    path: 'discountId'
  }
])

// Không có quyền thao tác discount
export const DiscountForbiddenException = new ForbiddenException([
  {
    message: 'Error.DiscountForbidden',
    path: 'discount'
  }
])

// Không sở hữu sản phẩm khi tạo discount
export const DiscountProductOwnershipException = new ForbiddenException([
  {
    message: 'Error.DiscountProductOwnership',
    path: 'productIds'
  }
])

// Discount đã hết lượt sử dụng
export const DiscountUsageLimitExceededException = new UnprocessableEntityException([
  {
    message: 'Error.DiscountUsageLimitExceeded',
    path: 'code'
  }
])

// Discount đã hết hạn
export const DiscountExpiredException = new UnprocessableEntityException([
  {
    message: 'Error.DiscountExpired',
    path: 'code'
  }
])

export const InvalidDiscountDateRangeException = new UnprocessableEntityException([
  {
    message: 'discount.discount.error.INVALID_DATE_RANGE',
    path: 'endDate'
  }
])

export const ShopVoucherWithProductsException = new UnprocessableEntityException([
  {
    message: 'discount.discount.error.SHOP_VOUCHER_WITH_PRODUCTS',
    path: 'productIds'
  }
])

export const ProductVoucherWithoutProductsException = new UnprocessableEntityException([
  {
    message: 'discount.discount.error.PRODUCT_VOUCHER_WITHOUT_PRODUCTS',
    path: 'productIds'
  }
])

export const InvalidMaxDiscountValueException = new UnprocessableEntityException([
  {
    message: 'discount.discount.error.INVALID_MAX_DISCOUNT_VALUE',
    path: 'maxDiscountValue'
  }
])

export const InvalidDiscountCodeFormatException = new UnprocessableEntityException([
  {
    message: 'discount.discount.error.INVALID_CODE_FORMAT',
    path: 'code'
  }
])
