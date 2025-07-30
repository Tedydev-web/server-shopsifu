import { Controller, Get, Post, Body, Param, Put, Query } from '@nestjs/common'
import { CartService } from './cart.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import {
  AddToCartBodyDTO,
  AddToCartResDTO,
  DeleteCartBodyDTO,
  GetCartItemParamsDTO,
  GetCartResDTO,
  UpdateCartItemBodyDTO
} from 'src/routes/cart/cart.dto'
import { ZodSerializerDto } from 'nestjs-zod'
import { PaginationQueryDTO } from 'src/shared/dtos/request.dto'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('cart')
export class CartController {
  constructor(private readonly cartService: CartService) {}

  @Get()
  @ZodSerializerDto(GetCartResDTO)
  getCart(@ActiveUser() user: AccessTokenPayload, @Query() query: PaginationQueryDTO) {
    return this.cartService.getCart(user, query as any)
  }

  @Post()
  @ZodSerializerDto(AddToCartResDTO)
  addToCart(@Body() body: AddToCartBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.cartService.addToCart(user, body as any)
  }

  @Put(':cartItemId')
  @ZodSerializerDto(AddToCartResDTO)
  updateCartItem(
    @ActiveUser() user: AccessTokenPayload,
    @Param() param: GetCartItemParamsDTO,
    @Body() body: UpdateCartItemBodyDTO
  ) {
    return this.cartService.updateCartItem({ user, cartItemId: param.cartItemId, body } as any)
  }

  @Post('delete')
  @ZodSerializerDto(MessageResDTO)
  deleteCart(@Body() body: DeleteCartBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.cartService.deleteCart(user, body as any)
  }
}
