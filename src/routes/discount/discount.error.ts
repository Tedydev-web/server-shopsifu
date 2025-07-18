import { NotFoundException, UnprocessableEntityException, ConflictException, ForbiddenException } from '@nestjs/common'

export const DiscountNotFoundException = new NotFoundException('Mã giảm giá không tồn tại')
export const DiscountCodeAlreadyExistsException = new ConflictException('Mã giảm giá đã tồn tại')
export const DiscountExpiredException = new UnprocessableEntityException('Mã giảm giá đã hết hạn')
export const DiscountUsageExceededException = new ForbiddenException('Mã giảm giá đã hết lượt sử dụng')
export const DiscountMinOrderValueException = new UnprocessableEntityException('Đơn hàng không đủ điều kiện áp dụng mã giảm giá')
export const DiscountUserUsageExceededException = new ForbiddenException('Bạn đã sử dụng hết số lần cho phép với mã giảm giá này')
export const DiscountInactiveException = new UnprocessableEntityException('Mã giảm giá chưa được kích hoạt hoặc đã bị vô hiệu hóa')
