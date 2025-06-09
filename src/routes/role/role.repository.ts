import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Role } from './role.model'
import { CreateRoleDto, UpdateRoleDto } from './role.dto'
import { Permission, Role as PrismaRole } from '@prisma/client' // Import Permission for type casting

// Helper type for Prisma's return when including PermissionsOnRoles with Permission
type RoleWithPermissionsOnRoles = PrismaRole & {
  permissions: ({
    permission: Permission
  } & {
    roleId: number
    permissionId: number
    assignedAt: Date
    assignedById: number | null
  })[]
}

@Injectable()
export class RoleRepository {
  constructor(private readonly prisma: PrismaService) {}

  private mapToRoleType(roleWithPor: RoleWithPermissionsOnRoles | null): Role | null {
    if (!roleWithPor) {
      return null
    }
    const { permissions, ...restOfRole } = roleWithPor
    return {
      ...restOfRole,
      permissions: permissions.map((por) => por.permission)
    }
  }

  async create(createRoleDto: CreateRoleDto): Promise<Role> {
    const { name, description, isSystemRole, permissionIds } = createRoleDto
    const createdRole = await this.prisma.role.create({
      data: {
        name,
        description,
        isSystemRole: isSystemRole ?? false,
        permissions: permissionIds?.length
          ? {
              create: permissionIds.map((pid) => ({
                permission: { connect: { id: pid } }
                // assignedById: userId, // You might want to set this if available
              }))
            }
          : undefined
      },
      include: {
        permissions: { include: { permission: true } }
      }
    })
    return this.mapToRoleType(createdRole)
  }

  async findAll(): Promise<Role[]> {
    const rolesWithPor = await this.prisma.role.findMany({
      include: {
        permissions: { include: { permission: true } }
      }
    })
    return rolesWithPor.map((role) => this.mapToRoleType(role))
  }

  async findById(id: number): Promise<Role | null> {
    const roleWithPor = await this.prisma.role.findUnique({
      where: { id },
      include: {
        permissions: { include: { permission: true } }
      }
    })
    return this.mapToRoleType(roleWithPor)
  }

  async findByName(name: string): Promise<Role | null> {
    const roleWithPor = await this.prisma.role.findUnique({
      where: { name },
      include: {
        permissions: { include: { permission: true } }
      }
    })
    return this.mapToRoleType(roleWithPor)
  }

  async update(id: number, updateRoleDto: UpdateRoleDto): Promise<Role> {
    const { name, description, isSystemRole, permissionIds } = updateRoleDto
    const dataToUpdate: any = {} // This disable is needed for flexible dataToUpdate object
    if (name !== undefined) dataToUpdate.name = name
    if (description !== undefined) dataToUpdate.description = description
    if (isSystemRole !== undefined) dataToUpdate.isSystemRole = isSystemRole

    if (permissionIds !== undefined) {
      // For many-to-many with explicit join table, updating permissions typically involves:
      // 1. Deleting existing join records for this role.
      // 2. Creating new join records for the new set of permissionIds.
      // This is done in a transaction to ensure atomicity.
      // Prisma's nested writes can simplify this if structured correctly.
      dataToUpdate.permissions = {
        deleteMany: { roleId: id }, // Delete all existing PermissionsOnRoles for this role
        create: permissionIds.map((pid) => ({
          permission: { connect: { id: pid } }
          // assignedById: userId, // Set if available and needed
        }))
      }
    }

    const updatedRole = await this.prisma.role.update({
      where: { id },
      data: dataToUpdate,
      include: {
        permissions: { include: { permission: true } }
      }
    })
    return this.mapToRoleType(updatedRole)
  }

  async deleteById(id: number): Promise<PrismaRole> {
    // Prisma automatically handles cascading deletes for related PermissionsOnRoles records
    // if the schema is defined with onDelete: Cascade for the relation.
    return this.prisma.role.delete({
      where: { id }
    })
  }
}
