import { z } from 'zod'
import { AddressSchema, UserSchema } from 'src/shared/models/shared-user.model'

export const UpdateMeBodySchema = UserSchema.pick({
  name: true,
  phoneNumber: true,
  avatar: true
}).strict()

export const ChangePasswordBodySchema = UserSchema.pick({
  password: true
})
  .extend({
    newPassword: z.string().min(6).max(100),
    confirmNewPassword: z.string().min(6).max(100)
  })
  .strict()
  .superRefine(({ newPassword, confirmNewPassword }, ctx) => {
    if (newPassword !== confirmNewPassword) {
      ctx.addIssue({
        code: 'custom',
        message: 'Error.ConfirmPasswordNotMatch',
        path: ['confirmNewPassword']
      })
    }
  })

export const CreateAddressBodySchema = AddressSchema.omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  createdById: true,
  updatedById: true,
  deletedAt: true,
  deletedById: true
})
  .partial({
    recipient: true,
    phoneNumber: true
  })
  .extend({
    isDefault: z.boolean().optional().default(false)
  })
  .strict()

export const UpdateAddressBodySchema = CreateAddressBodySchema.partial().strict()

export const GetAddressParamsSchema = z.object({
  addressId: z.string().uuid()
})

export const GetUserAddressesResSchema = z.object({
  message: z.string(),
  data: z.array(
    AddressSchema.extend({
      isDefault: z.boolean()
    })
  )
})

export const GetUserAddressDetailResSchema = z.object({
  message: z.string(),
  data: AddressSchema.extend({
    isDefault: z.boolean()
  })
})

export const CreateAddressResSchema = z.object({
  message: z.string(),
  data: AddressSchema.extend({
    isDefault: z.boolean()
  })
})

export const UpdateAddressResSchema = z.object({
  message: z.string(),
  data: AddressSchema.extend({
    isDefault: z.boolean()
  })
})

export const GetUserStatisticsResSchema = z.object({
  message: z.string(),
  data: z.object({
    totalOrders: z.number(),
    totalSpent: z.number(),
    memberSince: z.union([z.string(), z.date()])
  })
})

export type UpdateMeBodyType = z.infer<typeof UpdateMeBodySchema>
export type ChangePasswordBodyType = z.infer<typeof ChangePasswordBodySchema>

// Address types
export type CreateAddressBodyType = z.infer<typeof CreateAddressBodySchema>
export type UpdateAddressBodyType = z.infer<typeof UpdateAddressBodySchema>
export type GetAddressParamsType = z.infer<typeof GetAddressParamsSchema>
export type GetUserAddressesResType = z.infer<typeof GetUserAddressesResSchema>
export type GetUserAddressDetailResType = z.infer<typeof GetUserAddressDetailResSchema>
export type CreateAddressResType = z.infer<typeof CreateAddressResSchema>
export type UpdateAddressResType = z.infer<typeof UpdateAddressResSchema>
export type GetUserStatisticsResType = z.infer<typeof GetUserStatisticsResSchema>
