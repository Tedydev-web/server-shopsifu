import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

export class PermissionError {
  public static NotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'PERMISSION_NOT_FOUND', 'permission.error.notFound')
  }

  public static AlreadyExists(action: string, subject: string): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'PERMISSION_ALREADY_EXISTS', 'permission.error.alreadyExists', {
      action,
      subject
    })
  }

  public static CreateFailed(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'PERMISSION_CREATE_FAILED',
      'permission.error.createFailed'
    )
  }

  public static UpdateFailed(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'PERMISSION_UPDATE_FAILED',
      'permission.error.updateFailed'
    )
  }

  public static DeleteFailed(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'PERMISSION_DELETE_FAILED',
      'permission.error.deleteFailed'
    )
  }
}
