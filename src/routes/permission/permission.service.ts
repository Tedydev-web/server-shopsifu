import { Injectable, NotFoundException, ConflictException } from '@nestjs/common'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { PermissionRepository } from './permission.repository' // Added
import { Permission } from './permission.model' // Updated path
import { CreatePermissionDto, UpdatePermissionDto } from './permission.dto'

@Injectable()
export class PermissionService {
  constructor(
    private readonly permissionRepository: PermissionRepository, // Injected repository
    private readonly i18n: I18nService
  ) {}

  async create(createPermissionDto: CreatePermissionDto): Promise<Permission> {
    const { action, subject } = createPermissionDto

    const existingPermission = await this.permissionRepository.findByActionAndSubject(action, subject)

    if (existingPermission) {
      throw new ConflictException(
        this.i18n.t('rbac.PERMISSION_ALREADY_EXISTS', {
          lang: I18nContext.current()?.lang,
          args: { action, subject }
        })
      )
    }
    return this.permissionRepository.create(createPermissionDto)
  }

  async findAll(): Promise<Permission[]> {
    return this.permissionRepository.findAll()
  }

  async findOne(id: number): Promise<Permission> {
    const permission = await this.permissionRepository.findById(id)

    if (!permission) {
      throw new NotFoundException(
        this.i18n.t('rbac.PERMISSION_NOT_FOUND', {
          lang: I18nContext.current()?.lang,
          args: { id }
        })
      )
    }
    return permission
  }

  async update(id: number, updatePermissionDto: UpdatePermissionDto): Promise<Permission> {
    const currentPermission = await this.findOne(id) // Kiểm tra tồn tại và lấy permission hiện tại

    const { action, subject } = updatePermissionDto

    // Nếu action hoặc subject thay đổi, kiểm tra xung đột
    if ((action && action !== currentPermission.action) || (subject && subject !== currentPermission.subject)) {
      const newAction = action || currentPermission.action
      const newSubject = subject || currentPermission.subject

      const conflictingPermission = await this.permissionRepository.findByActionAndSubject(newAction, newSubject)

      if (conflictingPermission && conflictingPermission.id !== id) {
        throw new ConflictException(
          this.i18n.t('rbac.PERMISSION_ALREADY_EXISTS', {
            lang: I18nContext.current()?.lang,
            args: { action: newAction, subject: newSubject }
          })
        )
      }
    }
    // Repository's update method handles partial updates based on its implementation
    return this.permissionRepository.update(id, updatePermissionDto)
  }

  async remove(id: number): Promise<Permission> {
    await this.findOne(id) // Kiểm tra tồn tại

    return this.permissionRepository.remove(id)
  }
}
