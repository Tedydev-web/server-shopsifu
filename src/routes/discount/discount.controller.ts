import { Body, Controller, Delete, Get, Param, Post, Put, Query } from '@nestjs/common'
import { DiscountService } from './discount.service'
import {
  CreateDiscountBodyDTO,
  GetDiscountDetailResDTO,
  GetDiscountParamsDTO,
  GetDiscountsQueryDTO,
  GetDiscountsResDTO,
  UpdateDiscountBodyDTO
} from './discount.dto'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { ZodSerializerDto } from 'nestjs-zod'

@Controller('discounts')
export class DiscountController {
  constructor(private readonly discountService: DiscountService) {}

  /**
   * Tạo mã giảm giá (Shop/Admin)
   */
  @Post()
  @ZodSerializerDto(GetDiscountDetailResDTO)
  create(@Body() body: CreateDiscountBodyDTO, @ActiveUser('userId') userId: string) {
    // Nếu là shop thì shopId = userId, nếu là admin thì cần truyền shopId trong body hoặc xử lý phân quyền ở service
    const shopId = userId
    return this.discountService.createDiscount({ ...body, shopId, createdById: userId })
  }

  /**
   * Lấy danh sách mã giảm giá (User/Shop)
   */
  @Get()
  @ZodSerializerDto(GetDiscountsResDTO)
  list(@Query() query: GetDiscountsQueryDTO) {
    return this.discountService.getDiscounts(query)
  }

  /**
   * Lấy chi tiết mã giảm giá
   */
  @Get(':discountId')
  @ZodSerializerDto(GetDiscountDetailResDTO)
  detail(@Param() params: GetDiscountParamsDTO) {
    return this.discountService.getDiscountDetail(params.discountId)
  }

  /**
   * Cập nhật mã giảm giá
   */
  @Put(':discountId')
  @ZodSerializerDto(GetDiscountDetailResDTO)
  update(
    @Param() params: GetDiscountParamsDTO,
    @Body() body: UpdateDiscountBodyDTO,
    @ActiveUser('userId') userId: string
  ) {
    return this.discountService.updateDiscount(params.discountId, body, userId)
  }

  /**
   * Xóa mã giảm giá (Shop/Admin)
   */
  @Delete(':discountId')
  @ZodSerializerDto(GetDiscountDetailResDTO)
  delete(@Param() params: GetDiscountParamsDTO, @ActiveUser('userId') userId: string) {
    return this.discountService.deleteDiscount(params.discountId, userId)
  }

  /**
   * Lấy danh sách sản phẩm theo mã giảm giá
   */
  @Get('by-code/:code/products')
  getProductsByDiscountCode(@Param('code') code: string) {
    return this.discountService.getProductsByDiscountCode(code)
  }

  /**
   * Tính toán số tiền giảm giá cho user
   */
  @Get('amount')
  getDiscountAmount(
    @Query('code') code: string,
    @Query('userId') userId: string,
    @Query('orderValue') orderValue: number
  ) {
    return this.discountService.getDiscountAmount({ code, userId, orderValue: Number(orderValue) })
  }
}
