import { createZodDto } from 'nestjs-zod'
import { Permission } from './permission.model'
import { CreatePermissionZodSchema, UpdatePermissionZodSchema } from './permission.schema'

export class CreatePermissionDto extends createZodDto(CreatePermissionZodSchema) {}

export class UpdatePermissionDto extends createZodDto(UpdatePermissionZodSchema) {}

export class SimplePermissionItemDto {
  id: number
  action: string
  description: string | null
}

export class PermissionDto implements Omit<Permission, 'createdById' | 'updatedById' | 'deletedById' | 'uiMetadata'> {
  id: number
  action: string
  subject: string
  description: string | null
  conditions: Record<string, any> | null
  createdAt: Date
  updatedAt: Date
  deletedAt: Date | null
  isSystemPermission: boolean

  constructor(partial: Partial<PermissionDto>) {
    Object.assign(this, partial)
  }

  static fromEntity(entity: Permission): PermissionDto {
    return new PermissionDto({
      id: entity.id,
      action: entity.action,
      subject: entity.subject,
      description: entity.description,
      conditions: entity.conditions as Record<string, any> | null,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
      deletedAt: entity.deletedAt,
      isSystemPermission: entity.isSystemPermission
    })
  }
}
