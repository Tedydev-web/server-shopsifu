import { createZodDto } from 'nestjs-zod'
import { Permission } from '@prisma/client'
import { z } from 'zod'
import {
  GetGroupedPermissionsResponseSchema,
  GetPermissionsQuerySchema,
  PermissionGroupSchema,
  PermissionItemSchema,
  PermissionSchema
} from './permission.schema'

// ===================================================================================
//                                       DTOs
// ===================================================================================

// --- Request DTOs ---
export class GetPermissionsQueryDto extends createZodDto(GetPermissionsQuerySchema) {}
export class CreatePermissionDto extends createZodDto(PermissionSchema) {}
export class UpdatePermissionDto extends createZodDto(PermissionSchema.partial()) {}

// --- Response DTOs ---
export class GetGroupedPermissionsResponseDto extends createZodDto(GetGroupedPermissionsResponseSchema) {}

// Infer and export types from Zod schemas
export type PermissionGroup = z.infer<typeof PermissionGroupSchema>
export type PermissionItem = z.infer<typeof PermissionItemSchema>

export class PermissionDto implements Omit<Permission, 'createdById' | 'updatedById' | 'deletedById'> {
  id: number
  action: string
  subject: string
  description: string | null
  conditions: Record<string, any> | null
  uiMetadata: Record<string, any> | null
  createdAt: Date
  updatedAt: Date
  deletedAt: Date | null

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
      uiMetadata: entity.uiMetadata as Record<string, any> | null,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
      deletedAt: entity.deletedAt
    })
  }
}
