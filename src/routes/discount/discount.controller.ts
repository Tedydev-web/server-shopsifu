import { Controller, Get, Param, Query, Post, Body } from '@nestjs/common'
import { SkipThrottle } from '@nestjs/throttler'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  GetAvailableDiscountsResDTO,
  GetDiscountDetailResDTO,
  GetDiscountParamsDTO,
  GetDiscountsQueryDTO,
  GetDiscountsResDTO,
  VerifyDiscountBodyDTO,
  VerifyDiscountResDTO
} from './discount.dto'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { DiscountService } from './discount.service'

@SkipThrottle()
@Controller('discounts')
@IsPublic()
export class DiscountController {
  constructor(private readonly discountService: DiscountService) {}

  @Get()
  @ZodSerializerDto(GetDiscountsResDTO)
  list(@Query() query: GetDiscountsQueryDTO) {
    return this.discountService.list(query)
  }

  @SkipThrottle({ default: false })
  @Get('available')
  @ZodSerializerDto(GetAvailableDiscountsResDTO)
  async getAvailableDiscounts(@Query() query: GetDiscountsQueryDTO, @ActiveUser('userId') userId?: string) {
    return this.discountService.getAvailableDiscounts({ ...query, userId })
  }

  @SkipThrottle({ default: false })
  @Get(':discountId')
  @ZodSerializerDto(GetDiscountDetailResDTO)
  findById(@Param() params: GetDiscountParamsDTO) {
    return this.discountService.getDetail(params.discountId)
  }

  @Post('verify')
  @ZodSerializerDto(VerifyDiscountResDTO)
  async verifyDiscounts(@Body() body: VerifyDiscountBodyDTO, @ActiveUser('userId') userId?: string) {
    return this.discountService.verifyDiscounts({ ...body, userId })
  }
}
