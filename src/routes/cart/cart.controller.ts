import { Controller, Get, Post, Body, Param, Put, Query } from '@nestjs/common'
import { CartService } from './cart.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import {
  AddToCartBodyDTO,
  AddToCartResDTO,
  CartItemDTO,
  DeleteCartBodyDTO,
  GetCartItemParamsDTO,
  GetCartResDTO,
  UpdateCartItemBodyDTO
} from 'src/routes/cart/cart.dto'
import { ZodSerializerDto } from 'nestjs-zod'
import { PaginationQueryDTO } from 'src/shared/dtos/request.dto'

@Controller('cart')
export class CartController {
  constructor(private readonly cartService: CartService) {}

  @Get()
  @ZodSerializerDto(GetCartResDTO)
  getCart(@ActiveUser('userId') userId: string, @Query() query: PaginationQueryDTO) {
    return this.cartService.getCart(userId, query)
  }

  @Post()
  @ZodSerializerDto(AddToCartResDTO)
  addToCart(@Body() body: AddToCartBodyDTO, @ActiveUser('userId') userId: string) {
    return this.cartService.addToCart(userId, body)
  }

  @Put(':cartItemId')
  @ZodSerializerDto(AddToCartResDTO)
  updateCartItem(
    @ActiveUser('userId') userId: string,
    @Param() param: GetCartItemParamsDTO,
    @Body() body: UpdateCartItemBodyDTO
  ) {
    return this.cartService.updateCartItem({
      userId,
      cartItemId: param.cartItemId,
      body
    })
  }

  @Post('delete')
  @ZodSerializerDto(MessageResDTO)
  deleteCart(@Body() body: DeleteCartBodyDTO, @ActiveUser('userId') userId: string) {
    return this.cartService.deleteCart(userId, body)
  }
}
