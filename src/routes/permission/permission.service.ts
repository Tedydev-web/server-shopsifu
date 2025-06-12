import { Injectable, Logger } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { PermissionRepository } from './permission.repository'
import { Permission } from './permission.model'
import { CreatePermissionDto, UpdatePermissionDto, PermissionGroup } from './permission.dto'
import { PermissionError } from './permission.error'
import { I18nTranslations } from 'src/generated/i18n.generated'

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
    return this.permissionRepository.create(createPermissionDto)
  }

  async findAll(page?: number, limit?: number): Promise<Permission[]> {
    return this.permissionRepository.findAll(page, limit)
  }

  /**
   * Get permissions grouped by subject (similar to sessions grouped by device)
   * @param currentPage - Current page number (starts from 1)
   * @param itemsPerPage - Number of groups per page
   * @returns Grouped permissions with pagination metadata
   */
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

    // Get all permissions without pagination first
    const allPermissions = await this.permissionRepository.findAll()

    // Group permissions by subject
    const permissionGroups = new Map<string, Permission[]>()

    for (const permission of allPermissions) {
      const subject = permission.subject
      if (!permissionGroups.has(subject)) {
        permissionGroups.set(subject, [])
      }
      permissionGroups.get(subject)?.push(permission)
    }

    // Convert to PermissionGroup objects and sort
    const groups: PermissionGroup[] = []

    for (const [subject, permissions] of permissionGroups.entries()) {
      // Sort permissions within each group by action
      permissions.sort((a, b) => a.action.localeCompare(b.action))

      groups.push({
        subject,
        displayName: this.formatSubjectDisplayName(subject),
        permissionsCount: permissions.length,
        permissions: permissions.map((p) => ({
          id: p.id,
          action: p.action,
          httpMethod: this.getHttpMethodFromAction(p.action),
          endpoint: this.generateEndpointFromSubjectAndAction(p.subject, p.action)
        }))
      })
    }

    // Sort groups by subject name for consistency
    groups.sort((a, b) => a.subject.localeCompare(b.subject))

    // Apply pagination to groups
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

  /**
   * Format subject name for display (e.g., "User" -> "USERS")
   */
  private formatSubjectDisplayName(subject: string): string {
    return subject.toUpperCase()
  }

  /**
   * Get HTTP method from action name
   */
  private getHttpMethodFromAction(action: string): string {
    const actionLower = action.toLowerCase()

    if (actionLower.includes('create') || actionLower.includes('post')) {
      return 'POST'
    } else if (actionLower.includes('read') || actionLower.includes('get') || actionLower.includes('list')) {
      return 'GET'
    } else if (actionLower.includes('update') || actionLower.includes('patch') || actionLower.includes('edit')) {
      return 'PATCH'
    } else if (actionLower.includes('delete') || actionLower.includes('remove')) {
      return 'DELETE'
    }

    return 'GET' // Default fallback
  }

  /**
   * Generate API endpoint from subject and action
   */
  private generateEndpointFromSubjectAndAction(subject: string, action: string): string {
    const subjectLower = subject.toLowerCase()
    const actionLower = action.toLowerCase()

    // Convert subject to plural form for REST API convention
    const pluralSubject = this.pluralizeSubject(subjectLower)

    if (actionLower.includes('create') || actionLower.includes('post')) {
      return `/api/v1/${pluralSubject}`
    } else if (actionLower.includes('read') || actionLower.includes('get')) {
      if (actionLower.includes('list') || actionLower.includes('paginate')) {
        return `/api/v1/${pluralSubject}`
      } else {
        return `/api/v1/${pluralSubject}/:id`
      }
    } else if (actionLower.includes('update') || actionLower.includes('patch') || actionLower.includes('edit')) {
      return `/api/v1/${pluralSubject}/:id`
    } else if (actionLower.includes('delete') || actionLower.includes('remove')) {
      return `/api/v1/${pluralSubject}/:id`
    }

    return `/api/v1/${pluralSubject}` // Default fallback
  }

  /**
   * Convert subject to plural form for API endpoints
   */
  private pluralizeSubject(subject: string): string {
    const subjectLower = subject.toLowerCase()

    // Handle common irregular plurals
    const irregularPlurals: Record<string, string> = {
      company: 'companies',
      person: 'people',
      child: 'children',
      user: 'users',
      file: 'files',
      permission: 'permissions',
      role: 'roles'
    }

    if (irregularPlurals[subjectLower]) {
      return irregularPlurals[subjectLower]
    }

    // Handle regular plurals
    if (subjectLower.endsWith('y')) {
      return subjectLower.slice(0, -1) + 'ies'
    } else if (
      subjectLower.endsWith('s') ||
      subjectLower.endsWith('sh') ||
      subjectLower.endsWith('ch') ||
      subjectLower.endsWith('x') ||
      subjectLower.endsWith('z')
    ) {
      return subjectLower + 'es'
    } else {
      return subjectLower + 's'
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

    return this.permissionRepository.update(id, updatePermissionDto)
  }

  async remove(id: number): Promise<Permission> {
    await this.findOne(id) // Ensure permission exists
    return this.permissionRepository.remove(id)
  }
}
