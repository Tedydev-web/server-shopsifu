import { BadRequestException, NotFoundException, ForbiddenException } from '@nestjs/common'

export const DiscountCodeAlreadyExistsException = new BadRequestException('Mã discount đã tồn tại')
export const DiscountNotFoundException = new NotFoundException('Không tìm thấy discount')
export class DiscountUnauthorizedException extends ForbiddenException {
  constructor(message?: string) {
    super(message || 'Bạn không có quyền thao tác với discount này')
  }
}
