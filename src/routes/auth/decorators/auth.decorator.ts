import { SetMetadata, applyDecorators } from '@nestjs/common'
import { AuthType, ConditionGuard } from 'src/shared/constants/auth.constant'

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

export const PermissionsRequired = (...permissions: string[]) =>
  applyDecorators(SetMetadata('permissions', permissions))
