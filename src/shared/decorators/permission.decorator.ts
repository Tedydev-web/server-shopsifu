import { SetMetadata } from '@nestjs/common'
import { RequiredPermission, PERMISSIONS_KEY } from '../guards/permission.guard'

/**
 * Decorator to define required permissions for an endpoint
 * @param permissions Array of required permissions
 * @example
 * @RequirePermissions(
 *   { resource: 'user', action: 'read' },
 *   { resource: 'role', action: 'create' }
 * )
 */
export const RequirePermissions = (...permissions: RequiredPermission[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions)

/**
 * Shorthand decorators for common operations
 */
export const RequireRead = (resource: string) => RequirePermissions({ resource, action: 'read' })
export const RequireCreate = (resource: string) => RequirePermissions({ resource, action: 'create' })
export const RequireUpdate = (resource: string) => RequirePermissions({ resource, action: 'update' })
export const RequireDelete = (resource: string) => RequirePermissions({ resource, action: 'delete' })
export const RequireManage = (resource: string) => RequirePermissions({ resource, action: 'manage' }) 