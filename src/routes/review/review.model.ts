import { MediaType } from 'src/shared/constants/media.constant'
import { UserSchema } from 'src/shared/models/shared-user.model'
import { z } from 'zod'

export const ReviewMediaSchema = z.object({
  id: z.number().int(),
  url: z.string().max(1000),
  type: z.enum([MediaType.IMAGE, MediaType.VIDEO]),
  reviewId: z.number().int(),
  createdAt: z.date(),
})

export const ReviewSchema = z.object({
  id: z.number().int(),
  content: z.string(),
  rating: z.number().int().min(0).max(5),
  orderId: z.number().int(),
  productId: z.number().int(),
  userId: z.number().int(),
  updateCount: z.number().int(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export const CreateReviewBodySchema = ReviewSchema.pick({
  content: true,
  rating: true,
  productId: true,
  orderId: true,
}).extend({
  medias: z.array(
    ReviewMediaSchema.pick({
      url: true,
      type: true,
    }),
  ),
})

export const CreateReviewResSchema = ReviewSchema.extend({
  medias: z.array(ReviewMediaSchema),
  user: UserSchema.pick({
    id: true,
    name: true,
    avatar: true,
  }),
})

export const UpdateReviewResSchema = CreateReviewResSchema

export const GetReviewsSchema = z.object({
  data: z.array(CreateReviewResSchema),
  totalItems: z.number(),
  page: z.number(), // Số trang hiện tại
  limit: z.number(), // Số item trên 1 trang
  totalPages: z.number(), // Tổng số trang
})

export const UpdateReviewBodySchema = CreateReviewBodySchema
export const GetReviewsParamsSchema = z.object({
  productId: z.coerce.number().int().positive(),
})
export const GetReviewDetailParamsSchema = z.object({
  reviewId: z.coerce.number().int().positive(),
})

export type ReviewType = z.infer<typeof ReviewSchema>
export type ReviewMediaType = z.infer<typeof ReviewMediaSchema>
export type CreateReviewBodyType = z.infer<typeof CreateReviewBodySchema>
export type UpdateReviewBodyType = z.infer<typeof UpdateReviewBodySchema>
export type CreateReviewResType = z.infer<typeof CreateReviewResSchema>
export type UpdateReviewResType = z.infer<typeof UpdateReviewResSchema>
export type GetReviewsType = z.infer<typeof GetReviewsSchema>
