import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

function createApiError(status: HttpStatus, errorType: string, errorCode: string, fieldPath?: string) {
  return new ApiException(status, errorType, `error.${errorCode}`, [{ code: `error.${errorCode}`, path: fieldPath }])
}

export const InvalidOTPException = createApiError(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'ValidationError',
  'Error.Auth.Otp.Invalid',
  'code'
)

export const OTPExpiredException = createApiError(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'ValidationError',
  'Error.Auth.Otp.Expired',
  'code'
)

export const FailedToSendOTPException = createApiError(
  HttpStatus.INTERNAL_SERVER_ERROR,
  'InternalServerError',
  'Error.Auth.Otp.FailedToSend'
)

export const EmailAlreadyExistsException = createApiError(
  HttpStatus.CONFLICT,
  'ResourceConflict',
  'Error.Auth.Email.AlreadyExists',
  'email'
)

export const EmailNotFoundException = createApiError(
  HttpStatus.NOT_FOUND,
  'ResourceNotFound',
  'Error.Auth.Email.NotFound',
  'email'
)

export const InvalidPasswordException = createApiError(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'ValidationError',
  'Error.Auth.Password.Invalid',
  'password'
)

export const PasswordsDoNotMatchException = createApiError(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'ValidationError',
  'Error.Auth.Password.Mismatch',
  'password'
)

export const MissingAccessTokenException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Token.MissingAccessToken',
  'accessToken'
)

export const InvalidAccessTokenException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Token.InvalidAccessToken',
  'accessToken'
)

export const ExpiredAccessTokenException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Token.ExpiredAccessToken',
  'accessToken'
)

export const MissingRefreshTokenException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Token.MissingRefreshToken',
  'refreshToken'
)

export const InvalidRefreshTokenException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Token.InvalidRefreshToken',
  'refreshToken'
)

export const ExpiredRefreshTokenException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Token.ExpiredRefreshToken',
  'refreshToken'
)

export const RefreshTokenAlreadyUsedException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Token.RefreshTokenAlreadyUsed',
  'refreshToken'
)

export const UnauthorizedAccessException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Access.Unauthorized'
)

export const AccessDeniedException = createApiError(HttpStatus.FORBIDDEN, 'Forbidden', 'Error.Auth.Access.Denied')

export const InvalidLoginSessionException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Session.InvalidLogin'
)

export const InvalidTOTPException = createApiError(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'ValidationError',
  'Error.Auth.2FA.InvalidTOTP',
  'totpCode'
)

export const TOTPAlreadyEnabledException = createApiError(
  HttpStatus.CONFLICT,
  'ResourceConflict',
  'Error.Auth.2FA.AlreadyEnabled'
)

export const TOTPNotEnabledException = createApiError(
  HttpStatus.PRECONDITION_FAILED,
  'PreconditionFailed',
  'Error.Auth.2FA.NotEnabled'
)

export const InvalidRecoveryCodeException = createApiError(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'ValidationError',
  'Error.Auth.2FA.InvalidRecoveryCode',
  'code'
)

export const InvalidCodeFormatException = createApiError(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'ValidationError',
  'Error.Auth.2FA.InvalidCodeFormat',
  'code'
)

export const InvalidOTPTokenException = createApiError(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'ValidationError',
  'Error.Auth.OtpToken.Invalid',
  'otpToken'
)

export const OTPTokenExpiredException = createApiError(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'ValidationError',
  'Error.Auth.OtpToken.Expired',
  'otpToken'
)

export const InvalidDeviceException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Device.Invalid',
  'device'
)

export const DeviceMismatchException = createApiError(
  HttpStatus.BAD_REQUEST,
  'DeviceMismatch',
  'Error.Auth.Device.Mismatch'
)

export const DeviceSetupFailedException = createApiError(
  HttpStatus.INTERNAL_SERVER_ERROR,
  'InternalServerError',
  'Error.Auth.Device.SetupFailed',
  'device'
)

export const DeviceAssociationFailedException = createApiError(
  HttpStatus.INTERNAL_SERVER_ERROR,
  'InternalServerError',
  'Error.Auth.Device.AssociationFailed',
  'device'
)

export const TooManyOTPAttemptsException = createApiError(
  HttpStatus.TOO_MANY_REQUESTS,
  'TooManyOtpAttempts',
  'Error.Auth.Otp.TooManyAttempts'
)

export function createDeviceSetupFailedException(messageKey = 'Error.Auth.Device.SetupFailed') {
  return createApiError(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', messageKey, 'device')
}

export function createDeviceAssociationFailedException(messageKey = 'Error.Auth.Device.AssociationFailed') {
  return createApiError(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', messageKey, 'device')
}

export const GoogleUserInfoException = createApiError(
  HttpStatus.INTERNAL_SERVER_ERROR,
  'InternalServerError',
  'Error.Auth.Google.UserInfoFailed',
  'googleApi'
)

export const AbsoluteSessionLifetimeExceededException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Session.AbsoluteLifetimeExceeded'
)

export const DeviceMissingSessionCreationTimeException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Device.MissingSessionCreationTime'
)

export const RemoteSessionRevokedException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Session.RevokedRemotely'
)

export const MaxSessionsReachedException = createApiError(
  HttpStatus.TOO_MANY_REQUESTS,
  'LimitExceeded',
  'Error.Auth.Session.MaxSessionsReached'
)

export const MaxDevicesReachedException = createApiError(
  HttpStatus.TOO_MANY_REQUESTS,
  'LimitExceeded',
  'Error.Auth.Device.MaxDevicesReached'
)

export const SessionNotFoundException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Session.NotFound',
  'sessionId'
)

export const MismatchedSessionTokenException = createApiError(
  HttpStatus.UNAUTHORIZED,
  'Unauthenticated',
  'Error.Auth.Session.MismatchedToken',
  'session'
)
