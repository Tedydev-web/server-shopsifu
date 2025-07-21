import { ProductTranslationSchema } from 'src/shared/models/shared-product-translation.model'
import { ProductSchema } from 'src/shared/models/shared-product.model'
import { SKUSchema } from 'src/shared/models/shared-sku.model'
import { UserSchema } from 'src/shared/models/shared-user.model'
import { z } from 'zod'

export const CartItemSchema = z.object({
  id: z.string(),
  quantity: z.number().int().positive(),
  skuId: z.string(),
  userId: z.string(),

  createdAt: z.coerce.date(),
  updatedAt: z.coerce.date()
})

export const GetCartItemParamsSchema = z.object({
  cartItemId: z.string()
})

export const CartItemDetailSchema = z.object({
  message: z.string().optional(),
  shop: UserSchema.pick({
    id: true,
    name: true,
    avatar: true
  }),
  cartItems: z.array(
    CartItemSchema.extend({
      sku: SKUSchema.extend({
        product: ProductSchema.extend({
          productTranslations: z.array(
            ProductTranslationSchema.omit({
              createdById: true,
              updatedById: true,
              deletedById: true,
              deletedAt: true,
              createdAt: true,
              updatedAt: true
            })
          )
        }).omit({
          createdById: true,
          updatedById: true,
          deletedById: true,
          deletedAt: true,
          createdAt: true,
          updatedAt: true
        })
      }).omit({
        createdById: true,
        updatedById: true,
        deletedById: true,
        deletedAt: true,
        createdAt: true,
        updatedAt: true
      })
    })
  )
})

export const GetCartResSchema = z.object({
  message: z.string().optional(),
  data: z.array(CartItemDetailSchema),
  metadata: z.object({
    totalItems: z.number(),
    page: z.number(),
    limit: z.number(),
    totalPages: z.number(),
    hasNext: z.boolean(),
    hasPrev: z.boolean()
  })
})

export const AddToCartBodySchema = CartItemSchema.pick({
  skuId: true,
  quantity: true
}).strict()

export const UpdateCartItemBodySchema = AddToCartBodySchema

export const DeleteCartBodySchema = z
  .object({
    cartItemIds: z.array(z.string())
  })
  .strict()

export const AddToCartResSchema = z.object({
  message: z.string(),
  data: CartItemSchema
})

export type CartItemType = z.infer<typeof CartItemSchema>
export type GetCartItemParamType = z.infer<typeof GetCartItemParamsSchema>
export type CartItemDetailType = z.infer<typeof CartItemDetailSchema>
export type GetCartResType = z.infer<typeof GetCartResSchema>
export type AddToCartBodyType = z.infer<typeof AddToCartBodySchema>
export type UpdateCartItemBodyType = z.infer<typeof UpdateCartItemBodySchema>
export type DeleteCartBodyType = z.infer<typeof DeleteCartBodySchema>
export type AddToCartResType = z.infer<typeof AddToCartResSchema>
