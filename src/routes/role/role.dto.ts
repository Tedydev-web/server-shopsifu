import { IsString, IsNotEmpty, MaxLength, IsOptional, IsBoolean, IsArray, IsNumber } from 'class-validator'
import { PartialType } from '@nestjs/mapped-types'
import { Role } from '@prisma/client'

// Originally from create-role.dto.ts
export class CreateRoleDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name: string

  @IsOptional()
  @IsString()
  description?: string

  @IsOptional()
  @IsBoolean()
  isSystemRole?: boolean

  @IsOptional()
  @IsArray()
  @IsNumber({}, { each: true })
  permissionIds?: number[]
}

// Originally from update-role.dto.ts
// CreateRoleDto is now defined in the same file
export class UpdateRoleDto extends PartialType(CreateRoleDto) {}

// Originally from role.dto.ts (the old one)
export class RoleDto
  implements Omit<Role, 'createdById' | 'updatedById' | 'deletedById' | 'createdBy' | 'updatedBy' | 'deletedBy'>
{
  id: number
  name: string
  description: string | null
  isSystemRole: boolean
  createdAt: Date
  updatedAt: Date
  deletedAt: Date | null

  constructor(partial: Partial<RoleDto>) {
    Object.assign(this, partial)
  }

  // static fromEntity(entity: Role): RoleDto {
  //   return new RoleDto({
  //     id: entity.id,
  //     name: entity.name,
  //     description: entity.description,
  //     isSystemRole: entity.isSystemRole,
  //     createdAt: entity.createdAt,
  //     updatedAt: entity.updatedAt,
  //     deletedAt: entity.deletedAt,
  //   })
  // }
}
