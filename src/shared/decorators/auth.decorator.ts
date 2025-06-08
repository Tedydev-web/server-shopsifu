import { AuthType, ConditionGuard } from 'src/shared/constants/auth/auth.constants'
import { SetMetadata, applyDecorators } from '@nestjs/common'

// Auth Type Decorator
export const AUTH_TYPE_KEY = 'auth_type'

export interface AuthTypeDecoratorPayload {
  authTypes: string[]
  options: {
    condition: string
  }
}

export const Auth = (
  authTypes: string[] = [AuthType.JWT],
  options: { condition: string } = { condition: ConditionGuard.RolesAndPermissions }
) => {
  return applyDecorators(SetMetadata('auth_type', authTypes), SetMetadata('auth_options', options))
}

// Public decorator
export const IS_PUBLIC_KEY = 'is_public'
export const IsPublic = () => applyDecorators(SetMetadata('is_public', true))

// Roles decorator
export const ROLES_KEY = 'roles'
export const RolesAllowed = (...roles: string[]) => applyDecorators(SetMetadata('roles', roles))

// Permissions decorator
export const PERMISSIONS_KEY = 'permissions'
export const PermissionsRequired = (...permissions: string[]) =>
  applyDecorators(SetMetadata(PERMISSIONS_KEY, permissions))
