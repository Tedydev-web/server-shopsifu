import { MediaType } from 'src/shared/constants/media.constant'
import { UserSchema } from 'src/shared/models/shared-user.model'
import { z } from 'zod'

export const ReviewMediaSchema = z.object({
  id: z.string(),
  url: z.string().max(1000),
  type: z.nativeEnum(MediaType),
  reviewId: z.string(),
  createdAt: z.union([z.string(), z.date()])
})

export const ReviewSchema = z.object({
  id: z.string(),
  content: z.string(),
  rating: z.number().int().min(0).max(5),
  orderId: z.string(),
  productId: z.string(),
  userId: z.string(),
  updateCount: z.number().int(),
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()])
})

export const CreateReviewBodySchema = ReviewSchema.pick({
  content: true,
  rating: true,
  productId: true,
  orderId: true
}).extend({
  medias: z.array(
    ReviewMediaSchema.pick({
      url: true,
      type: true
    })
  )
})

export const CreateReviewResSchema = z.object({
  message: z.string().optional(),
  data: ReviewSchema.extend({
    medias: z.array(ReviewMediaSchema),
    user: UserSchema.pick({
      id: true,
      name: true,
      avatar: true
    })
  })
})

export const UpdateReviewResSchema = CreateReviewResSchema

export const GetReviewsSchema = z.object({
  message: z.string().optional(),
  data: z.array(CreateReviewResSchema),
  metadata: z.object({
    totalItems: z.number(),
    page: z.number(),
    limit: z.number(),
    totalPages: z.number(),
    hasNext: z.boolean(),
    hasPrev: z.boolean()
  })
})

export const UpdateReviewBodySchema = CreateReviewBodySchema
export const GetReviewsParamsSchema = z.object({
  productId: z.string()
})
export const GetReviewDetailParamsSchema = z.object({
  reviewId: z.string()
})

export type ReviewType = z.infer<typeof ReviewSchema>
export type ReviewMediaType = z.infer<typeof ReviewMediaSchema>
export type CreateReviewBodyType = z.infer<typeof CreateReviewBodySchema>
export type UpdateReviewBodyType = z.infer<typeof UpdateReviewBodySchema>
export type CreateReviewResType = z.infer<typeof CreateReviewResSchema>
export type UpdateReviewResType = z.infer<typeof UpdateReviewResSchema>
export type GetReviewsType = z.infer<typeof GetReviewsSchema>
