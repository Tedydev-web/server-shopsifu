import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { PERMISSIONS_KEY, RequiredPermission } from '../decorators/required-permissions.decorator'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { RoleService } from '../../routes/role/role.service'
import { PermissionService } from '../../routes/permission/permission.service'

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly i18n: I18nService,
    private readonly roleService: RoleService,
    private readonly permissionService: PermissionService
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.getAllAndOverride<RequiredPermission[]>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass()
    ])

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true
    }

    const { user } = context.switchToHttp().getRequest()

    if (!user || !user.id) {
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
