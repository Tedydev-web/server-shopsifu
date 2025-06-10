import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

export class UserError {
  public static NotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'USER_NOT_FOUND', 'user.error.notFound')
  }

  public static AlreadyExists(email: string): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'USER_ALREADY_EXISTS', 'user.error.alreadyExists', { email })
  }

  public static CreateFailed(): ApiException {
    return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'USER_CREATE_FAILED', 'user.error.createFailed')
  }

  public static UpdateFailed(): ApiException {
    return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'USER_UPDATE_FAILED', 'user.error.updateFailed')
  }

  public static DeleteFailed(): ApiException {
    return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'USER_DELETE_FAILED', 'user.error.deleteFailed')
  }
}
