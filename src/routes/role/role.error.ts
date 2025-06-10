import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

export class RoleError {
  public static NotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'ROLE_NOT_FOUND', 'role.error.notFound')
  }

  public static AlreadyExists(name: string): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'ROLE_ALREADY_EXISTS', 'role.error.alreadyExists', { name })
  }

  public static CreateFailed(): ApiException {
    return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ROLE_CREATE_FAILED', 'role.error.createFailed')
  }

  public static UpdateFailed(): ApiException {
    return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ROLE_UPDATE_FAILED', 'role.error.updateFailed')
  }

  public static DeleteFailed(): ApiException {
    return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ROLE_DELETE_FAILED', 'role.error.deleteFailed')
  }

  public static CannotDeleteSystemRole(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'CANNOT_DELETE_SYSTEM_ROLE', 'role.error.cannotDeleteSystemRole')
  }

  public static CannotUpdateSystemRole(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'CANNOT_UPDATE_SYSTEM_ROLE', 'role.error.cannotUpdateSystemRole')
  }
}
