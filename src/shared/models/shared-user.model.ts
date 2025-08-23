import { AddressType, UserStatus } from 'src/shared/constants/user.constant'
import { PermissionSchema } from 'src/shared/models/shared-permission.model'
import { RoleSchema } from 'src/shared/models/shared-role.model'
import { z } from 'zod'

export const UserSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  name: z.string().min(1).max(100),
  password: z.string().min(6).max(100),
  phoneNumber: z.union([z.string().min(9).max(15), z.null()]).optional(),
  avatar: z.string().nullable(),
  totpSecret: z.string().nullable(),
  status: z.nativeEnum(UserStatus),
  roleId: z.string(),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.union([z.string(), z.date()]).nullable(),
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()])
})

export const AddressSchema = z.object({
  id: z.string(),
  name: z.string().min(1).max(500),
  recipient: z.string().min(1).max(500).optional(),
  phoneNumber: z.string().min(9).max(15).optional(),
  province: z.string().min(1).max(200).optional(),
  district: z.string().min(1).max(200).optional(),
  ward: z.string().min(1).max(200).optional(),

  // GHN ID fields for API integration
  provinceId: z.number().int().positive().nullable(),
  districtId: z.number().int().positive().nullable(),
  wardCode: z.string().max(20).nullable(),

  street: z.string().min(1).max(500).optional(),
  addressType: z.nativeEnum(AddressType),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.union([z.string(), z.date()]).nullable(),
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()])
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
      memberSince: z.union([z.string(), z.date()])
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
