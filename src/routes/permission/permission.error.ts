import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

function createApiError(
  status: HttpStatus,
  errorType: string,
  errorCode: string,
  fieldPath?: string,
  args?: Record<string, any>
) {
  return new ApiException(status, errorType, errorCode, [{ code: errorCode, path: fieldPath, args }])
}

export const PermissionAlreadyExistsException = createApiError(
  HttpStatus.CONFLICT,
  'ResourceConflict',
  'Error.Permission.AlreadyExists',
  'name'
)

export const PermissionNotFoundException = (permissionId: number) =>
  createApiError(HttpStatus.NOT_FOUND, 'ResourceNotFound', 'Error.Permission.NotFound', 'permissionId', {
    id: permissionId
  })

export const PermissionDeletedException = (permissionId: number) =>
  createApiError(HttpStatus.GONE, 'ResourceDeleted', 'Error.Permission.Deleted', 'permissionId', { id: permissionId })

export const PermissionInUseException = (permissionId: number) =>
  createApiError(HttpStatus.CONFLICT, 'ResourceInUse', 'Error.Permission.InUse', 'permissionId', { id: permissionId })

export const PathMethodCombinationExistsException = createApiError(
  HttpStatus.CONFLICT,
  'ResourceConflict',
  'Error.Permission.PathMethodCombinationExists',
  'path'
)

export const PermissionActionForbiddenException = createApiError(
  HttpStatus.FORBIDDEN,
  'Forbidden',
  'Error.Permission.ActionForbidden'
)
