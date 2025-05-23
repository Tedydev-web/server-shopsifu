import { HttpStatus } from '@nestjs/common'
import { ApiException, ErrorDetailMessage } from 'src/shared/exceptions/api.exception'

function createApiError(
  status: HttpStatus,
  errorType: string,
  errorCode: string,
  fieldPath?: string,
  args?: Record<string, any>
): ApiException {
  const details: ErrorDetailMessage[] = []
  if (fieldPath) {
    details.push({ code: errorCode, path: fieldPath, args })
  } else {
    details.push({ code: errorCode, args })
  }
  return new ApiException(status, errorType, errorCode, details)
}

export const RoleNotFoundException = (roleId: number) =>
  createApiError(HttpStatus.NOT_FOUND, 'ResourceNotFound', 'Error.Role.NotFound', 'roleId', { id: roleId })

export const RoleDeletedException = (roleId: number) =>
  createApiError(HttpStatus.GONE, 'ResourceDeleted', 'Error.Role.Deleted', 'roleId', { id: roleId })

export const RoleInUseException = (roleId: number) =>
  createApiError(HttpStatus.CONFLICT, 'ResourceInUse', 'Error.Role.InUse', 'roleId', { id: roleId })

export const RoleNameAlreadyExistsException = (name: string) =>
  createApiError(HttpStatus.CONFLICT, 'ResourceConflict', 'Error.Role.Name.AlreadyExists', 'name', { name })

export const RoleActionForbiddenException = (reason?: string) =>
  createApiError(
    HttpStatus.FORBIDDEN,
    'Forbidden',
    'Error.Role.ActionForbidden',
    undefined,
    reason ? { reason } : undefined
  )

export const CannotDeleteSystemRoleException = (roleName: string) =>
  createApiError(HttpStatus.FORBIDDEN, 'Forbidden', 'Error.Role.CannotDeleteSystemRole', 'roleId', {
    name: roleName
  })
