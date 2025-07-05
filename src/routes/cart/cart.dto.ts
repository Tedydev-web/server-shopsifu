import { createZodDto } from 'nestjs-zod'
import {
  AddToCartBodySchema,
  CartItemSchema,
  DeleteCartBodySchema,
  GetCartItemParamsSchema,
  GetCartResSchema,
  UpdateCartItemBodySchema,
} from 'src/routes/cart/cart.model'

export class CartItemDTO extends createZodDto(CartItemSchema) {}

export class GetCartResDTO extends createZodDto(GetCartResSchema) {}

export class GetCartItemParamsDTO extends createZodDto(GetCartItemParamsSchema) {}
export class AddToCartBodyDTO extends createZodDto(AddToCartBodySchema) {}

export class UpdateCartItemBodyDTO extends createZodDto(UpdateCartItemBodySchema) {}

export class DeleteCartBodyDTO extends createZodDto(DeleteCartBodySchema) {}
