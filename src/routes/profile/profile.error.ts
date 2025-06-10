import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

export class ProfileError {
  public static NotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'PROFILE_NOT_FOUND', 'profile.error.notFound')
  }

  public static UpdateFailed(): ApiException {
    return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'PROFILE_UPDATE_FAILED', 'profile.error.updateFailed')
  }

  public static AlreadyExists(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'PROFILE_ALREADY_EXISTS', 'profile.error.alreadyExists')
  }
}
