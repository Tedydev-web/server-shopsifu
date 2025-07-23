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
