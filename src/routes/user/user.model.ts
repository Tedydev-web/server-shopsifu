import { z } from 'zod'
import { UserSchema } from 'src/shared/models/shared-user.model'
import { RoleSchema } from 'src/shared/models/shared-role.model'

export const GetUsersResSchema = z.object({
  message: z.string().optional(),
  data: z.array(
    UserSchema.omit({ password: true, totpSecret: true }).extend({
      role: RoleSchema.pick({
        id: true,
        name: true
      })
    })
  ),
  metadata: z.object({
    totalItems: z.number(),
    page: z.number(),
    limit: z.number(),
    totalPages: z.number(),
    hasNext: z.boolean(),
    hasPrev: z.boolean()
  })
})

export const GetUsersQuerySchema = z
  .object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().positive().default(10)
  })
  .strict()

export const GetUserParamsSchema = z
  .object({
    userId: z.string()
  })
  .strict()

export const CreateUserBodySchema = UserSchema.pick({
  email: true,
  name: true,
  phoneNumber: true,
  avatar: true,
  status: true,
  password: true,
  roleId: true
}).strict()

export const UpdateUserBodySchema = CreateUserBodySchema.partial()

export type GetUsersResType = z.infer<typeof GetUsersResSchema>
export type GetUsersQueryType = z.infer<typeof GetUsersQuerySchema>
export type GetUserParamsType = z.infer<typeof GetUserParamsSchema>
export type CreateUserBodyType = z.infer<typeof CreateUserBodySchema>
export type UpdateUserBodyType = z.infer<typeof UpdateUserBodySchema>
