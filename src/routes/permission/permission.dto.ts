import { IsString, IsNotEmpty, MaxLength, IsOptional } from 'class-validator'
import { PartialType } from '@nestjs/mapped-types'
import { Permission } from '@prisma/client'

// Originally from create-permission.dto.ts
export class CreatePermissionDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(50) // HTTP methods or CRUD actions are usually short
  action: string // e.g., 'CREATE', 'GET', 'MANAGE_USERS'

  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  subject: string // e.g., 'users', '/api/v1/resource/:id', 'ProductEntity'

  @IsOptional()
  @IsString()
  @MaxLength(255)
  description?: string

  @IsOptional()
  @IsString()
  @MaxLength(100)
  category?: string // e.g., 'UserManagement', 'Products', 'general'
}

// Originally from update-permission.dto.ts
// CreatePermissionDto is now defined in the same file
export class UpdatePermissionDto extends PartialType(CreatePermissionDto) {
  // Các trường action, subject, description, category sẽ được kế thừa
  // và là optional do PartialType.
  // Không cần định nghĩa lại ở đây trừ khi muốn override decorator hoặc thêm logic.
}

// Originally from permission.dto.ts (the old one)
export class PermissionDto
  implements Omit<Permission, 'createdById' | 'updatedById' | 'deletedById' | 'createdBy' | 'updatedBy' | 'deletedBy'>
{
  id: number
  action: string
  subject: string
  description: string | null
  category: string | null
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
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
      deletedAt: entity.deletedAt
    })
  }
}
