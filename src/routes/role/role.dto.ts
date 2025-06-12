import { createZodDto } from 'nestjs-zod'
import { Role } from '@prisma/client'
import { RoleSchema } from './role.schema'

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
