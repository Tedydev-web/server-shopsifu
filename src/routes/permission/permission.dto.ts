import { createZodDto } from 'nestjs-zod'
import { Permission } from '@prisma/client'
import { z } from 'zod'

// ===================================================================================
//                                Interface & Helper Types
// ===================================================================================
export interface PermissionUiMetadata {
  uiPath?: string
  httpMethod?: string
  apiEndpoint?: string
  description?: string
}

const PermissionUiMetadataZodSchema = z.object({
  uiPath: z.string().optional(),
  httpMethod: z.string().optional(),
  apiEndpoint: z.string().optional(),
  description: z.string().optional()
})

// ===================================================================================
//                                       DTOs
// ===================================================================================

// --- Request DTOs ---
const CreatePermissionZodSchema = z.object({
  action: z.string().min(1),
  subject: z.string().min(1),
  description: z.string().optional(),
  conditions: z.any().optional(),
  uiMetadata: PermissionUiMetadataZodSchema.optional()
})
export class CreatePermissionDto extends createZodDto(CreatePermissionZodSchema) {}

const UpdatePermissionZodSchema = z.object({
  action: z.string().min(1).optional(),
  subject: z.string().min(1).optional(),
  description: z.string().optional(),
  conditions: z.any().optional(),
  uiMetadata: PermissionUiMetadataZodSchema.optional()
})
export class UpdatePermissionDto extends createZodDto(UpdatePermissionZodSchema) {}

// ===================================================================================
//                            SIMPLE DTOs FOR UI
// ===================================================================================
export class SimplePermissionItemDto {
  id: number
  action: string
  description: string | null
}

// ===================================================================================
//                                Full Entity DTOs
// ===================================================================================
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
      uiMetadata: entity.uiMetadata as Record<string, any> | null,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
      deletedAt: entity.deletedAt,
      isSystemPermission: entity.isSystemPermission
    })
  }
}
