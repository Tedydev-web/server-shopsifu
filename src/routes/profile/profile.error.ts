import { HttpStatus } from '@nestjs/common'
import { ApiException, ErrorDetailMessage } from 'src/shared/exceptions/api.exception'

function createProfileApiError(
  status: HttpStatus,
  errorCode: string,
  messageKey: string,
  details?: ErrorDetailMessage[] | ErrorDetailMessage
): ApiException {
  return new ApiException(status, errorCode, messageKey, details)
}

export const ProfileError = {
  EmailUnchanged: () =>
    createProfileApiError(HttpStatus.BAD_REQUEST, 'EMAIL_UNCHANGED', 'Error.Profile.Email.Unchanged'),
  EmailAlreadyExists: (email: string) =>
    createProfileApiError(HttpStatus.CONFLICT, 'EMAIL_ALREADY_EXISTS', 'Error.Profile.Email.AlreadyExists', {
      path: 'email',
      code: 'Error.Profile.Email.AlreadyExists',
      args: { email }
    }),
  PendingEmailMatchesCurrent: () =>
    createProfileApiError(
      HttpStatus.BAD_REQUEST,
      'PENDING_EMAIL_MATCHES_CURRENT',
      'Error.Profile.PendingEmail.MatchesCurrent'
    ),
  NoPendingEmailChange: () =>
    createProfileApiError(HttpStatus.BAD_REQUEST, 'NO_PENDING_EMAIL_CHANGE', 'Error.Profile.Email.NoPendingChange'),
  InvalidEmailVerificationToken: () =>
    createProfileApiError(
      HttpStatus.BAD_REQUEST,
      'INVALID_EMAIL_VERIFICATION_TOKEN',
      'Error.Profile.Email.InvalidVerificationToken'
    ),
  EmailVerificationTokenExpired: () =>
    createProfileApiError(
      HttpStatus.BAD_REQUEST,
      'EMAIL_VERIFICATION_TOKEN_EXPIRED',
      'Error.Profile.Email.VerificationTokenExpired'
    ),
  CurrentEmailAlreadyVerified: () =>
    createProfileApiError(
      HttpStatus.BAD_REQUEST,
      'CURRENT_EMAIL_ALREADY_VERIFIED',
      'Error.Profile.Email.AlreadyVerified'
    ),
  UpdateFailed: () =>
    createProfileApiError(HttpStatus.INTERNAL_SERVER_ERROR, 'PROFILE_UPDATE_FAILED', 'Error.Profile.UpdateFailed'),
  UsernameLengthInvalid: (min: number, max: number) =>
    createProfileApiError(HttpStatus.BAD_REQUEST, 'USERNAME_LENGTH_INVALID', 'Error.Profile.Username.Length', {
      path: 'username',
      code: 'Error.Profile.Username.Length',
      args: { min, max }
    }),
  UsernameInvalidChars: () =>
    createProfileApiError(HttpStatus.BAD_REQUEST, 'USERNAME_INVALID_CHARS', 'Error.Profile.Username.InvalidChars', {
      path: 'username',
      code: 'Error.Profile.Username.InvalidChars'
    }),
  UsernameTaken: (username: string) =>
    createProfileApiError(HttpStatus.CONFLICT, 'USERNAME_TAKEN', 'Error.Profile.Username.Taken', {
      path: 'username',
      code: 'Error.Profile.Username.Taken',
      args: { username }
    })
}
