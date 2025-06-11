import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { Permission } from '@prisma/client'

const PermissionSchema = z.object({
  action: z
    .string()
    .min(1, { message: 'Action is required' })
    .max(100, { message: 'Action must be 100 characters or less' }),
  subject: z
    .string()
    .min(1, { message: 'Subject is required' })
    .max(255, { message: 'Subject must be 255 characters or less' }),
  description: z.string().max(500).optional().nullable(),
  category: z.string().max(100).optional().nullable(),
  conditions: z.record(z.any()).optional().nullable()
})

export class CreatePermissionDto extends createZodDto(PermissionSchema) {}

export class UpdatePermissionDto extends createZodDto(PermissionSchema.partial()) {}

export class PermissionDto implements Omit<Permission, 'createdById' | 'updatedById' | 'deletedById'> {
  id: number
  action: string
  subject: string
  description: string | null
  category: string | null
  conditions: Record<string, any> | null
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
      category: entity.category,
      conditions: entity.conditions as Record<string, any> | null,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
      deletedAt: entity.deletedAt
    })
  }
}
