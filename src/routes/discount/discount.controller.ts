import { Body, Controller, Post } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { DiscountService } from './discount.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { GetAvailableDiscountsBodyDTO, GetAvailableDiscountsResDTO } from './discount.dto'

@Controller('discounts')
export class DiscountController {
  constructor(private readonly discountService: DiscountService) {}

  @Post('available')
  @ZodSerializerDto(GetAvailableDiscountsResDTO)
  getAvailableForCheckout(@Body() body: GetAvailableDiscountsBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.discountService.getAvailableForCheckout({ cartItemIds: body.cartItemIds, userId: user.userId })
  }
}
