import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { Role } from '@prisma/client'

const RoleSchema = z.object({
  name: z.string().min(1, { message: 'Name is required' }).max(100),
  description: z.string().max(500).optional().nullable(),
  isSystemRole: z.boolean().optional(),
  isSuperAdmin: z.boolean().optional(),
  permissionIds: z.array(z.number().int().positive()).optional()
})

export class CreateRoleDto extends createZodDto(RoleSchema) {}

export class UpdateRoleDto extends createZodDto(RoleSchema.partial()) {}

export class RoleDto
  implements Omit<Role, 'createdById' | 'updatedById' | 'deletedById' | 'createdBy' | 'updatedBy' | 'deletedBy'>
{
  id: number
  name: string
  description: string | null
  isSystemRole: boolean
  isSuperAdmin: boolean
  createdAt: Date
  updatedAt: Date
  deletedAt: Date | null

  constructor(partial: Partial<RoleDto>) {
    Object.assign(this, partial)
  }

  static fromEntity(entity: Role): RoleDto {
    return new RoleDto({
      id: entity.id,
      name: entity.name,
      description: entity.description,
      isSystemRole: entity.isSystemRole,
      isSuperAdmin: entity.isSuperAdmin,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
      deletedAt: entity.deletedAt
    })
  }
}
