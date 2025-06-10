import { Injectable } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { PermissionRepository } from './permission.repository'
import { Permission } from './permission.model'
import { CreatePermissionDto, UpdatePermissionDto } from './permission.dto'
import { PermissionError } from './permission.error'
import { I18nTranslations } from 'src/generated/i18n.generated'

@Injectable()
export class PermissionService {
  constructor(
    private readonly permissionRepository: PermissionRepository,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  async create(createPermissionDto: CreatePermissionDto): Promise<Permission> {
    const { action, subject } = createPermissionDto
    const existingPermission = await this.permissionRepository.findByActionAndSubject(action, subject)
    if (existingPermission) {
      throw PermissionError.AlreadyExists(action, subject)
    }
    return this.permissionRepository.create(createPermissionDto)
  }

  async findAll(): Promise<Permission[]> {
    return this.permissionRepository.findAll()
  }

  async findOne(id: number): Promise<Permission> {
    const permission = await this.permissionRepository.findById(id)
    if (!permission) {
      throw PermissionError.NotFound()
    }
    return permission
  }

  async update(id: number, updatePermissionDto: UpdatePermissionDto): Promise<Permission> {
    await this.findOne(id) // Ensure permission exists

    const { action, subject } = updatePermissionDto
    if (action && subject) {
      const conflictingPermission = await this.permissionRepository.findByActionAndSubject(action, subject)
      if (conflictingPermission && conflictingPermission.id !== id) {
        throw PermissionError.AlreadyExists(action, subject)
      }
    }

    return this.permissionRepository.update(id, updatePermissionDto)
  }

  async remove(id: number): Promise<Permission> {
    await this.findOne(id) // Ensure permission exists
    return this.permissionRepository.remove(id)
  }
}
