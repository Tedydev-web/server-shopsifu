import { Injectable, Logger } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { CreatePermissionDto, UpdatePermissionDto, SimplePermissionItemDto } from './permission.dto'
import { PermissionError } from './permission.error'
import { Permission } from './permission.model'
import { CreatePermissionData, PermissionRepository, UpdatePermissionData } from './permission.repository'

@Injectable()
export class PermissionService {
  private readonly logger = new Logger(PermissionService.name)

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
    const data: CreatePermissionData = {
      action: createPermissionDto.action,
      subject: createPermissionDto.subject,
      description: createPermissionDto.description,
      conditions: createPermissionDto.conditions,
      uiMetadata: createPermissionDto.uiMetadata ? createPermissionDto.uiMetadata : undefined
    }
    return this.permissionRepository.create(data)
  }

  async getAllGroupedPermissions(): Promise<Record<string, SimplePermissionItemDto[]>> {
    this.logger.debug(`[getAllGroupedPermissions] Getting all grouped permissions`)
    const allPermissions = await this.permissionRepository.findAll()
    const groupedPermissions: Record<string, SimplePermissionItemDto[]> = {}

    for (const permission of allPermissions) {
      if (!groupedPermissions[permission.subject]) {
        groupedPermissions[permission.subject] = []
      }
      groupedPermissions[permission.subject].push({
        id: permission.id,
        action: permission.action,
        description: permission.description
      })
    }

    // Sort subjects alphabetically
    const sortedGroupedPermissions: Record<string, SimplePermissionItemDto[]> = {}
    Object.keys(groupedPermissions)
      .sort()
      .forEach((subject) => {
        // Sort permissions within each subject alphabetically by action
        sortedGroupedPermissions[subject] = groupedPermissions[subject].sort((a, b) => a.action.localeCompare(b.action))
      })

    return sortedGroupedPermissions
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
    const data: UpdatePermissionData = {
      ...updatePermissionDto,
      uiMetadata: updatePermissionDto.uiMetadata ? updatePermissionDto.uiMetadata : undefined
    }
    return this.permissionRepository.update(id, data)
  }

  async remove(id: number): Promise<Permission> {
    await this.findOne(id) // Ensure permission exists
    return this.permissionRepository.remove(id)
  }
}
