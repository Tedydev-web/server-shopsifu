import { Controller, Get, Post, Param, Query, Body } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { DiscountService } from './discount.service'
import {
  GetDiscountsQueryDTO,
  GetDiscountsResDTO,
  GetDiscountParamsDTO,
  GetDiscountDetailResDTO,
  ValidateDiscountCodeBodyDTO,
  ValidateDiscountCodeResDTO
} from './discount.dto'

@Controller('public/discounts')
export class PublicDiscountController {
  constructor(private readonly discountService: DiscountService) {}

  @Get()
  @ZodSerializerDto(GetDiscountsResDTO)
  list(@Query() query: GetDiscountsQueryDTO) {
    return this.discountService.list(query as any)
  }

  @Get(':discountId')
  @ZodSerializerDto(GetDiscountDetailResDTO)
  findById(@Param() params: GetDiscountParamsDTO) {
    return this.discountService.getDetail(params.discountId)
  }

  @Post('validate-code')
  @ZodSerializerDto(ValidateDiscountCodeResDTO)
  validateCode(@Body() body: ValidateDiscountCodeBodyDTO) {
    return this.discountService.validateCode(body.code)
  }
}
