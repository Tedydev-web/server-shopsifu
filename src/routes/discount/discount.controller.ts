import { Controller, Get, Post, Query, Body, UseGuards } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { DiscountService } from './discount.service'
import { AccessTokenGuard } from 'src/shared/guards/access-token.guard'
import {
  GetAvailableDiscountsQueryDTO,
  GetAvailableDiscountsResDTO,
  ValidateVoucherCodeBodyDTO,
  ValidateVoucherCodeResDTO
} from './discount.dto'
import { IsPublic } from 'src/shared/decorators/auth.decorator'

@Controller('discounts')
@UseGuards(AccessTokenGuard)
export class DiscountController {
  constructor(private readonly discountService: DiscountService) {}

  @Get('available')
  @IsPublic()
  @ZodSerializerDto(GetAvailableDiscountsResDTO)
  getAvailableDiscounts(@Query() query: GetAvailableDiscountsQueryDTO) {
    return this.discountService.getAvailableDiscounts(query as any)
  }

  @Post('validate-code')
  @ZodSerializerDto(ValidateVoucherCodeResDTO)
  validateVoucherCode(@Body() body: ValidateVoucherCodeBodyDTO) {
    return this.discountService.validateVoucherCode(body as any)
  }
}
