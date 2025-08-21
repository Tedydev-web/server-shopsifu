import { AddressType, UserStatus } from 'src/shared/constants/user.constant'
import { PermissionSchema } from 'src/shared/models/shared-permission.model'
import { RoleSchema } from 'src/shared/models/shared-role.model'
import { z } from 'zod'

export const UserSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  name: z.string().min(1).max(500), // Cập nhật từ max(100) thành max(500) để phù hợp với database
  password: z.string().min(6).max(500), // Cập nhật từ max(100) thành max(500) để phù hợp với database
  phoneNumber: z.string().min(9).max(50), // Cập nhật từ max(15) thành max(50) để phù hợp với database
  avatar: z.string().max(1000).nullable(), // Thêm max(1000) để phù hợp với database
  totpSecret: z.string().max(1000).nullable(), // Thêm max(1000) để phù hợp với database
  status: z.nativeEnum(UserStatus),
  roleId: z.string(),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

/**
 * Schema validation cho dữ liệu Google OAuth
 */
export const GoogleUserDataSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(500).optional().default(''),
  picture: z
    .string()
    .max(1000)
    .nullable()
    .optional()
    .default(null)
    .transform((val) => {
      // Nếu URL avatar quá dài, cắt ngắn hoặc để null
      if (val && val.length > 1000) {
        console.warn('Google avatar URL too long, truncating:', val.length, 'characters')
        return val.substring(0, 1000)
      }
      return val
    })
})

export type GoogleUserDataType = z.infer<typeof GoogleUserDataSchema>

export const AddressSchema = z.object({
  id: z.string(),
  name: z.string().min(1).max(500),
  recipient: z.string().min(1).max(500).optional(),
  phoneNumber: z.string().min(9).max(50).optional(),
  province: z.string().min(1).max(200).optional(),
  district: z.string().min(1).max(200).optional(),
  ward: z.string().min(1).max(200).optional(),
  street: z.string().min(1).max(500).optional(),
  addressType: z.nativeEnum(AddressType),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

/**
 * Áp dụng cho Response của api GET('profile') và GET('users/:userId')
 */
export const GetUserProfileResSchema = z.object({
  message: z.string().optional(),
  data: UserSchema.omit({
    password: true,
    totpSecret: true,
    roleId: true
  }).extend({
    role: RoleSchema.pick({
      id: true,
      name: true
    }).extend({
      permissions: z.array(
        PermissionSchema.pick({
          id: true,
          name: true,
          module: true,
          path: true,
          method: true
        })
      )
    }),
    addresses: z.array(
      AddressSchema.extend({
        isDefault: z.boolean()
      })
    ),
    statistics: z.object({
      totalOrders: z.number(),
      totalSpent: z.number(),
      memberSince: z.date()
    })
  })
})

/**
 * Áp dụng cho Response của api PUT('profile') và PUT('users/:userId')
 */
export const UpdateProfileResSchema = z.object({
  data: UserSchema.omit({
    password: true,
    totpSecret: true
  }),
  message: z.string().optional()
})

export type UserType = z.infer<typeof UserSchema>
export type AddressType = z.infer<typeof AddressSchema>
export type GetUserProfileResType = z.infer<typeof GetUserProfileResSchema>
export type UpdateProfileResType = z.infer<typeof UpdateProfileResSchema>
