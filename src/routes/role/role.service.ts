import { Injectable, ForbiddenException } from '@nestjs/common'
import { RoleRepository } from './role.repository'
import { CreateRoleDto, UpdateRoleDto } from './role.dto'
import { Role } from './role.model'
import { RoleError } from './role.error'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'

@Injectable()
export class RoleService {
  constructor(
    private readonly roleRepository: RoleRepository,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async create(createRoleDto: CreateRoleDto): Promise<Role> {
    const existingRole = await this.roleRepository.findByName(createRoleDto.name)
    if (existingRole) {
      throw RoleError.AlreadyExists(createRoleDto.name)
    }
    // For now, we allow creating system/superadmin roles via API,
    // but this could be restricted to specific users (e.g., only super admins) in the controller layer using policies.
    return this.roleRepository.create(createRoleDto)
  }

  async findAll(): Promise<Role[]> {
    return this.roleRepository.findAll()
  }

  async findOne(id: number): Promise<Role> {
    const role = await this.roleRepository.findById(id)
    if (!role) {
      throw RoleError.NotFound()
    }
    return role
  }

  async update(id: number, updateRoleDto: UpdateRoleDto): Promise<Role> {
    const role = await this.findOne(id) // uses findOne to ensure role exists

    if (role.isSystemRole) {
      // Prevent key attributes from being changed on system roles
      if (
        updateRoleDto.isSystemRole === false ||
        updateRoleDto.isSuperAdmin === false ||
        (updateRoleDto.name && updateRoleDto.name !== role.name)
      ) {
        throw new ForbiddenException(this.i18n.t('role.error.cannotUpdateSystemRole'))
      }
    }

    // Prevent changing a role's name if it's a super admin role (to avoid breaking hard-coded logic if any remains)
    if (role.isSuperAdmin && updateRoleDto.name && updateRoleDto.name !== role.name) {
      throw new ForbiddenException('Cannot change the name of a super admin role.')
    }

    if (updateRoleDto.name && updateRoleDto.name !== role.name) {
      const existingRole = await this.roleRepository.findByName(updateRoleDto.name)
      if (existingRole && existingRole.id !== id) {
        throw RoleError.AlreadyExists(updateRoleDto.name)
      }
    }

    return this.roleRepository.update(id, updateRoleDto)
  }

  async remove(id: number): Promise<Role> {
    const role = await this.findOne(id) // uses findOne to ensure role exists

    if (role.isSystemRole) {
      throw RoleError.CannotDeleteSystemRole()
    }

    if (role.isSuperAdmin) {
      throw new ForbiddenException('Cannot delete a super admin role.')
    }

    return this.roleRepository.deleteById(id)
  }
}
