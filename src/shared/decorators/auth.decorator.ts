import { AuthType, AuthTypeType, ConditionGuard, ConditionGuardType } from 'src/routes/auth/auth.constants'
import { SetMetadata, UseGuards, applyDecorators } from '@nestjs/common'
import { AuthenticationGuard } from '../guards/authentication.guard'

// Auth Type Decorator
export const AUTH_TYPE_KEY = 'auth_type'
export const AUTH_OPTIONS_KEY = 'auth_options'

export const Auth = (
  authTypes: AuthTypeType[] = [AuthType.JWT],
  options: { condition: ConditionGuardType } = { condition: ConditionGuard.RolesAndPermissions }
) => {
  return applyDecorators(
    SetMetadata(AUTH_TYPE_KEY, authTypes),
    SetMetadata(AUTH_OPTIONS_KEY, options),
    UseGuards(AuthenticationGuard)
  )
}

// Public decorator
export const IS_PUBLIC_KEY = 'is_public'
export const IsPublic = () => SetMetadata(IS_PUBLIC_KEY, true)

// Roles decorator
export const ROLES_KEY = 'roles'
export const RolesAllowed = (...roles: string[]) => SetMetadata(ROLES_KEY, roles)

// Permissions decorator
export const PERMISSIONS_KEY = 'permissions'
export const PermissionsRequired = (...permissions: string[]) => SetMetadata(PERMISSIONS_KEY, permissions)
