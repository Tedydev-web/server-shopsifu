import { Body, Controller, Delete, Get, Param, Post, Put, Query, Req } from '@nestjs/common'
import { DiscountService } from './discount.service'
import {
  CreateDiscountBodyDTO,
  DiscountDetailResDTO,
  DiscountListQueryDTO,
  DiscountListResDTO,
  DiscountParamsDTO,
  UpdateDiscountBodyDTO,
  VerifyDiscountBodyDTO
} from './discount.dto'
import { Request } from 'express'

@Controller('discounts')
export class DiscountController {
  constructor(private readonly discountService: DiscountService) {}

  /**
   * ADMIN/SELLER: Tạo mới discount
   */
  @Post()
  async create(@Body() body: CreateDiscountBodyDTO, @Req() req: Request) {
    const { userId, roleName } = req['user'] || {}
    return this.discountService.create({ data: body, createdById: userId, roleName })
  }

  /**
   * ADMIN/SELLER/CLIENT: Lấy danh sách discount (filter, phân trang)
   */
  @Get()
  async list(@Query() query: DiscountListQueryDTO, @Req() req: Request) {
    const { userId, roleName } = req['user'] || {}
    return this.discountService.list({ ...query, userId, roleName })
  }

  /**
   * ADMIN/SELLER/CLIENT: Lấy chi tiết discount
   */
  @Get(':discountId')
  async detail(@Param() params: DiscountParamsDTO, @Req() req: Request) {
    const { userId, roleName } = req['user'] || {}
    return this.discountService.detail({ id: params.discountId, userId, roleName })
  }

  /**
   * ADMIN/SELLER: Cập nhật discount
   */
  @Put(':discountId')
  async update(@Param() params: DiscountParamsDTO, @Body() body: UpdateDiscountBodyDTO, @Req() req: Request) {
    const { userId, roleName } = req['user'] || {}
    return this.discountService.update({ id: params.discountId, data: body, updatedById: userId, roleName })
  }

  /**
   * ADMIN/SELLER: Xóa discount (mềm/hard)
   */
  @Delete(':discountId')
  async delete(@Param() params: DiscountParamsDTO, @Req() req: Request) {
    const { userId, roleName } = req['user'] || {}
    return this.discountService.delete({ id: params.discountId, deletedById: userId, roleName })
  }

  /**
   * CLIENT/GUEST: Lấy voucher khả dụng cho cart/order
   */
  @Get('available')
  async getAvailableDiscounts(@Query() query: any, @Req() req: Request) {
    const { userId } = req['user'] || {}
    return this.discountService.getAvailableDiscounts({ ...query, userId })
  }

  /**
   * CLIENT: Verify/apply voucher cho đơn hàng
   */
  @Post('verify')
  async verifyDiscounts(@Body() body: any, @Req() req: Request) {
    const { userId } = req['user'] || {}
    // Đảm bảo truyền cart (danh sách sản phẩm trong đơn hàng) vào service
    return this.discountService.verifyDiscounts({ ...body, userId, cart: body.cart || [] })
  }
}
