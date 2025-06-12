import { Injectable, Logger } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { CreatePermissionDto, PermissionGroup, UpdatePermissionDto, PermissionUiMetadata } from './permission.dto'
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

  async findAll(page?: number, limit?: number): Promise<Permission[]> {
    return this.permissionRepository.findAll(page, limit)
  }

  async getGroupedPermissions(
    currentPage: number = 1,
    itemsPerPage: number = 10
  ): Promise<{
    message: string
    data: {
      groups: PermissionGroup[]
      meta: {
        currentPage: number
        totalPages: number
        totalGroups: number
      }
    }
  }> {
    this.logger.debug(
      `[getGroupedPermissions] Getting grouped permissions for page: ${currentPage}, limit: ${itemsPerPage}`
    )

    const allPermissions = await this.permissionRepository.findAll()
    const permissionGroups = new Map<string, Permission[]>()

    for (const permission of allPermissions) {
      const subject = permission.subject
      if (!permissionGroups.has(subject)) {
        permissionGroups.set(subject, [])
      }
      permissionGroups.get(subject)?.push(permission)
    }

    const groups: PermissionGroup[] = []

    for (const [subject, permissions] of permissionGroups.entries()) {
      permissions.sort((a, b) => a.action.localeCompare(b.action))

      groups.push({
        subject,
        permissionsCount: permissions.length,
        permissions: permissions.map((p) => {
          const uiMetadata = p.uiMetadata as PermissionUiMetadata | null

          return {
            id: p.id,
            action: p.action,
            httpMethod: uiMetadata?.httpMethod || null,
            endpoint: uiMetadata?.apiEndpoint || null
          }
        })
      })
    }

    groups.sort((a, b) => a.subject.localeCompare(b.subject))

    const totalGroups = groups.length
    const totalPages = Math.ceil(totalGroups / itemsPerPage)
    const startIndex = (currentPage - 1) * itemsPerPage
    const paginatedGroups = groups.slice(startIndex, startIndex + itemsPerPage)

    return {
      message: 'permission.success.list',
      data: {
        groups: paginatedGroups,
        meta: {
          currentPage,
          totalPages,
          totalGroups
        }
      }
    }
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
