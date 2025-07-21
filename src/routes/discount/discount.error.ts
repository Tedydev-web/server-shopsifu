import { BadRequestException, NotFoundException, ForbiddenException } from '@nestjs/common'

export const DiscountCodeAlreadyExistsException = new BadRequestException('Mã giảm giá đã tồn tại')
export const DiscountNotFoundException = new NotFoundException('Không tìm thấy mã giảm giá')
export const DiscountUnauthorizedException = new ForbiddenException('Bạn không có quyền thao tác với mã giảm giá này')

// Có thể bổ sung thêm các exception đặc thù khác nếu cần
