import { Body, Controller, Post } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { DiscountService } from './discount.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('discounts')
export class DiscountController {
  constructor(private readonly discountService: DiscountService) {}

  @Post('available-for-checkout')
  @ZodSerializerDto(GetAvailableDiscountsResDTO)
  getAvailableForCheckout(@Body() body: GetAvailableDiscountsBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.discountService.getAvailableForCheckout(body.cartItemIds, user.userId)
  }
}
