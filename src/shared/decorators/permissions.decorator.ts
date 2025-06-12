import { SetMetadata } from '@nestjs/common'
import { Action, Subjects } from 'src/shared/casl/casl-ability.factory'
import { Type } from '@nestjs/common'

export const PERMISSIONS_KEY = 'permissions'

/**
 * @description Defines a single permission requirement for an endpoint.
 */
export interface RequiredPermission {
  action: Action
  /**
   * @description The subject of the permission.
   * Can be a string (e.g., 'Profile', 'all') for general permissions,
   * or a Model class (e.g., User, Role) for permissions that require
   * checking against a specific resource instance (for conditional permissions).
   */
  subject: Type<any> | Extract<Subjects, string>
}

/**
 * Decorator to specify the permissions required to access a route.
 *
 * @example
 * // Requires permission to create a user
 * @RequirePermissions({ action: Action.Create, subject: 'User' })
 *
 * @example
 * // Requires permission to update a specific user, will trigger resource loading
 * @RequirePermissions({ action: Action.Update, subject: User })
 *
 * @param permissions - A list of RequiredPermission objects.
 */
export const RequirePermissions = (...permissions: RequiredPermission[]) => SetMetadata(PERMISSIONS_KEY, permissions)
