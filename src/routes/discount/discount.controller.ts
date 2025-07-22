import { Controller, Get, Query, Post, Body } from '@nestjs/common'
import { SkipThrottle } from '@nestjs/throttler'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  GetAvailableDiscountsQueryDTO,
  GetAvailableDiscountsResDTO,
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

  @Get('available')
  @ZodSerializerDto(GetAvailableDiscountsResDTO)
  list(@Query() query: GetAvailableDiscountsQueryDTO, @ActiveUser('userId') userId?: string) {
    return this.discountService.getAvailableDiscounts({ ...query, userId })
  }

  @Post('verify')
  @ZodSerializerDto(VerifyDiscountResDTO)
  verify(@Body() body: VerifyDiscountBodyDTO, @ActiveUser('userId') userId?: string) {
    return this.discountService.verifyDiscounts({ ...body, userId })
  }
}
