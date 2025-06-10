import { Injectable } from '@nestjs/common'
import { RoleRepository } from './role.repository'
import { CreateRoleDto, UpdateRoleDto } from './role.dto'
import { Role } from './role.model'
import { RoleError } from './role.error'

@Injectable()
export class RoleService {
  constructor(private readonly roleRepository: RoleRepository) {}

  async create(createRoleDto: CreateRoleDto): Promise<Role> {
    const existingRole = await this.roleRepository.findByName(createRoleDto.name)
    if (existingRole) {
      throw RoleError.AlreadyExists(createRoleDto.name)
    }
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
    const role = await this.roleRepository.findById(id)
    if (!role) {
      throw RoleError.NotFound()
    }
    if (role.isSystemRole) {
      throw RoleError.CannotUpdateSystemRole()
    }
    return this.roleRepository.update(id, updateRoleDto)
  }

  async remove(id: number): Promise<Role> {
    const role = await this.roleRepository.findById(id)
    if (!role) {
      throw RoleError.NotFound()
    }
    if (role.isSystemRole) {
      throw RoleError.CannotDeleteSystemRole()
    }
    return this.roleRepository.deleteById(id)
  }
}
