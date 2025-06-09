import { ConflictException, Injectable, NotFoundException } from '@nestjs/common'
import { RoleRepository } from './role.repository' // Added
import { CreateRoleDto, UpdateRoleDto } from './role.dto'
import { Role } from './role.model' // Updated path

@Injectable()
export class RoleService {
  constructor(private readonly roleRepository: RoleRepository) {} // Injected repository

  async create(createRoleDto: CreateRoleDto): Promise<Role> {
    const existingRoleByName = await this.roleRepository.findByName(createRoleDto.name)

    if (existingRoleByName) {
      throw new ConflictException(`Vai trò với tên '${createRoleDto.name}' đã tồn tại.`)
    }

    // The repository's create method handles permissionIds
    return this.roleRepository.create(createRoleDto)
  }

  async findAll(): Promise<Role[]> {
    return this.roleRepository.findAll()
  }

  async findOne(id: number): Promise<Role> {
    const role = await this.roleRepository.findById(id)

    if (!role) {
      throw new NotFoundException(`Vai trò với ID '${id}' không tìm thấy.`)
    }
    return role
  }

  async update(id: number, updateRoleDto: UpdateRoleDto): Promise<Role> {
    const existingRole = await this.roleRepository.findById(id)
    if (!existingRole) {
      throw new NotFoundException(`Vai trò với ID '${id}' không tìm thấy.`)
    }

    if (updateRoleDto.name && updateRoleDto.name !== existingRole.name) {
      const roleWithSameName = await this.roleRepository.findByName(updateRoleDto.name)
      if (roleWithSameName && roleWithSameName.id !== id) {
        throw new ConflictException(`Một vai trò khác với tên '${updateRoleDto.name}' đã tồn tại.`)
      }
    }

    // The repository's update method handles permissionIds and partial updates
    return this.roleRepository.update(id, updateRoleDto)
  }

  async remove(id: number): Promise<Role> {
    const role = await this.roleRepository.findById(id)
    if (!role) {
      throw new NotFoundException(`Vai trò với ID ${id} không tồn tại.`)
    }
    if (role.isSystemRole) {
      throw new ConflictException('Không thể xóa vai trò hệ thống.')
    }
    await this.roleRepository.deleteById(id) // Call the new deleteById method
    return role // Return the role data that was fetched and checked
  }
}
