import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { PERMISSIONS_KEY, RequiredPermission } from '../decorators/required-permissions.decorator'
import { I18nService, I18nContext } from 'nestjs-i18n'
// import { RbacService } from '../../routes/rbac/services/rbac.service' // Old RbacService
import { RoleService } from '../../routes/role/role.service' // New RoleService
import { PermissionService } from '../../routes/permission/permission.service' // New PermissionService

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly i18n: I18nService,
    // private readonly rbacService: RbacService, // Old RbacService
    private readonly roleService: RoleService, // New RoleService
    private readonly permissionService: PermissionService // New PermissionService
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.getAllAndOverride<RequiredPermission[]>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass()
    ])

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true // No specific permissions required, allow access
    }

    const { user } = context.switchToHttp().getRequest()

    if (!user || !user.id) {
      // This should ideally be caught by JwtAuthGuard first
      throw new ForbiddenException(this.i18n.t('common.UNAUTHENTICATED', { lang: I18nContext.current()?.lang }))
    }

    // const userPermissions: RequiredPermission[] = await this.rbacService.getUserPermissions(user.id)
    // TODO: Implement logic to get user permissions using RoleService and/or PermissionService
    // For now, let's assume the user has no permissions to see if the dependency injection works
    const userPermissions: RequiredPermission[] = []

    const hasAllRequiredPermissions = requiredPermissions.every((requiredPermission) =>
      userPermissions.some(
        (userPerm) => userPerm.action === requiredPermission.action && userPerm.subject === requiredPermission.subject
      )
    )

    if (hasAllRequiredPermissions) {
      return true
    }

    throw new ForbiddenException(this.i18n.t('common.FORBIDDEN_RESOURCE', { lang: I18nContext.current()?.lang }))
  }
}
