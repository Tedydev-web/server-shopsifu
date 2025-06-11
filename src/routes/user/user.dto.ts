import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { UserStatus } from '@prisma/client'

const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters long')
  .max(100, 'Password must be at most 100 characters long')

export const CreateUserSchema = z.object({
  email: z.string().email(),
  password: passwordSchema,
  roleId: z.number().int(),
  status: z.nativeEnum(UserStatus).optional()
})

export const UpdateUserSchema = CreateUserSchema.partial().extend({
  // email should not be updatable this way to avoid conflicts.
  // A separate flow for changing email is recommended.
  email: z.string().email().optional().describe('Email update not recommended here'),
  password: passwordSchema.optional()
})

export class CreateUserDto extends createZodDto(CreateUserSchema) {}
export class UpdateUserDto extends createZodDto(UpdateUserSchema) {}

export const UserResponseSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  status: z.nativeEnum(UserStatus),
  roleId: z.number().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export class UserDto extends createZodDto(UserResponseSchema) {
  constructor(partial: Partial<UserDto>) {
    super()
    Object.assign(this, partial)
  }

  static fromEntity(entity: any): UserDto {
    return new UserDto({
      id: entity.id,
      email: entity.email,
      status: entity.status,
      roleId: entity.roleId,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt
    })
  }
}
