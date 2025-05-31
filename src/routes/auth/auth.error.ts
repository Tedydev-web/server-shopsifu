import { HttpStatus } from '@nestjs/common'
import { ApiException as BaseApiException } from 'src/shared/exceptions/api.exception'

export class InvalidOTPException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNPROCESSABLE_ENTITY, 'ValidationError', 'error.Error.Auth.Otp.Invalid', [
      { code: 'error.Error.Auth.Otp.Invalid', path: 'code' }
    ])
  }
}

export class OTPExpiredException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNPROCESSABLE_ENTITY, 'ValidationError', 'error.Error.Auth.Otp.Expired', [
      { code: 'error.Error.Auth.Otp.Expired', path: 'code' }
    ])
  }
}

export class FailedToSendOTPException extends BaseApiException {
  constructor() {
    super(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'error.Error.Auth.Otp.FailedToSend', [
      { code: 'error.Error.Auth.Otp.FailedToSend', path: 'otp' }
    ])
  }
}

export class EmailAlreadyExistsException extends BaseApiException {
  constructor() {
    super(HttpStatus.CONFLICT, 'ResourceConflict', 'error.Error.Auth.Email.AlreadyExists', [
      { code: 'error.Error.Auth.Email.AlreadyExists', path: 'email' }
    ])
  }
}

export class EmailNotFoundException extends BaseApiException {
  constructor() {
    super(HttpStatus.NOT_FOUND, 'ResourceNotFound', 'error.Error.Auth.Email.NotFound', [
      { code: 'error.Error.Auth.Email.NotFound', path: 'email' }
    ])
  }
}

export class InvalidPasswordException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNPROCESSABLE_ENTITY, 'ValidationError', 'error.Error.Auth.Password.Invalid', [
      { code: 'error.Error.Auth.Password.Invalid', path: 'password' }
    ])
  }
}

export class PasswordsDoNotMatchException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNPROCESSABLE_ENTITY, 'ValidationError', 'error.Error.Auth.Password.Mismatch', [
      { code: 'error.Error.Auth.Password.Mismatch', path: 'password' }
    ])
  }
}

export class MissingAccessTokenException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Token.MissingAccessToken', [
      { code: 'error.Error.Auth.Token.MissingAccessToken', path: 'accessToken' }
    ])
  }
}

export class InvalidAccessTokenException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Token.InvalidAccessToken', [
      { code: 'error.Error.Auth.Token.InvalidAccessToken', path: 'accessToken' }
    ])
  }
}

export class ExpiredAccessTokenException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Token.ExpiredAccessToken', [
      { code: 'error.Error.Auth.Token.ExpiredAccessToken', path: 'accessToken' }
    ])
  }
}

export class MissingRefreshTokenException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Token.MissingRefreshToken', [
      { code: 'error.Error.Auth.Token.MissingRefreshToken', path: 'refreshToken' }
    ])
  }
}

export class InvalidRefreshTokenException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Token.InvalidRefreshToken', [
      { code: 'error.Error.Auth.Token.InvalidRefreshToken', path: 'refreshToken' }
    ])
  }
}

export class ExpiredRefreshTokenException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Token.ExpiredRefreshToken', [
      { code: 'error.Error.Auth.Token.ExpiredRefreshToken', path: 'refreshToken' }
    ])
  }
}

export class RefreshTokenAlreadyUsedException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Token.RefreshTokenAlreadyUsed', [
      { code: 'error.Error.Auth.Token.RefreshTokenAlreadyUsed', path: 'refreshToken' }
    ])
  }
}

export class UnauthorizedAccessException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Access.Unauthorized')
  }
}

export class AccessDeniedException extends BaseApiException {
  constructor() {
    super(HttpStatus.FORBIDDEN, 'Forbidden', 'error.Error.Auth.Access.Denied')
  }
}

export class InvalidLoginSessionException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Session.InvalidLogin')
  }
}

export class InvalidTOTPException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNPROCESSABLE_ENTITY, 'ValidationError', 'error.Error.Auth.2FA.InvalidTOTP', [
      { code: 'error.Error.Auth.2FA.InvalidTOTP', path: 'totpCode' }
    ])
  }
}

export class TOTPAlreadyEnabledException extends BaseApiException {
  constructor() {
    super(HttpStatus.CONFLICT, 'ResourceConflict', 'error.Error.Auth.2FA.AlreadyEnabled')
  }
}

export class TOTPNotEnabledException extends BaseApiException {
  constructor() {
    super(HttpStatus.PRECONDITION_FAILED, 'PreconditionFailed', 'error.Error.Auth.2FA.NotEnabled')
  }
}

export class InvalidRecoveryCodeException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNPROCESSABLE_ENTITY, 'ValidationError', 'error.Error.Auth.2FA.InvalidRecoveryCode', [
      { code: 'error.Error.Auth.2FA.InvalidRecoveryCode', path: 'code' }
    ])
  }
}

export class InvalidCodeFormatException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNPROCESSABLE_ENTITY, 'ValidationError', 'error.Error.Auth.2FA.InvalidCodeFormat', [
      { code: 'error.Error.Auth.2FA.InvalidCodeFormat', path: 'code' }
    ])
  }
}

export class InvalidPasswordReverificationTokenException extends BaseApiException {
  constructor() {
    super(
      HttpStatus.UNAUTHORIZED,
      'PasswordReverificationError',
      'error.Error.Auth.PasswordReverification.InvalidToken',
      [{ code: 'error.Error.Auth.PasswordReverification.InvalidToken', path: 'reverificationToken' }]
    )
  }
}

export class InvalidOTPTokenException extends BaseApiException {
  constructor() {
    super(HttpStatus.BAD_REQUEST, 'SltContextError', 'error.Error.Auth.SltContext.Invalid', [
      { code: 'error.Error.Auth.SltContext.Invalid', path: 'sltCookie' }
    ])
  }
}

export class OTPTokenExpiredException extends BaseApiException {
  constructor() {
    super(HttpStatus.BAD_REQUEST, 'SltContextError', 'error.Error.Auth.SltContext.Expired', [
      { code: 'error.Error.Auth.SltContext.Expired', path: 'sltCookie' }
    ])
  }
}

export class InvalidDeviceException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Device.Invalid', [
      { code: 'error.Error.Auth.Device.Invalid', path: 'device' }
    ])
  }
}

export class DeviceMismatchException extends BaseApiException {
  constructor() {
    super(HttpStatus.BAD_REQUEST, 'DeviceMismatch', 'error.Error.Auth.Device.Mismatch')
  }
}

export class DeviceSetupFailedException extends BaseApiException {
  constructor() {
    super(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'error.Error.Auth.Device.SetupFailed', [
      { code: 'error.Error.Auth.Device.SetupFailed', path: 'device' }
    ])
  }
}

export class DeviceAssociationFailedException extends BaseApiException {
  constructor() {
    super(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'error.Error.Auth.Device.AssociationFailed', [
      { code: 'error.Error.Auth.Device.AssociationFailed', path: 'device' }
    ])
  }
}

export class TooManyOTPAttemptsException extends BaseApiException {
  constructor() {
    super(HttpStatus.TOO_MANY_REQUESTS, 'TooManyOtpAttempts', 'error.Error.Auth.Otp.TooManyAttempts')
  }
}

export class GoogleUserInfoException extends BaseApiException {
  constructor() {
    super(HttpStatus.INTERNAL_SERVER_ERROR, 'InternalServerError', 'error.Error.Auth.Google.UserInfoFailed', [
      { code: 'error.Error.Auth.Google.UserInfoFailed', path: 'googleApi' }
    ])
  }
}

export class AbsoluteSessionLifetimeExceededException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Session.AbsoluteLifetimeExceeded')
  }
}

export class DeviceMissingSessionCreationTimeException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Device.MissingSessionCreationTime')
  }
}

export class RemoteSessionRevokedException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Session.RevokedRemotely')
  }
}

export class MaxSessionsReachedException extends BaseApiException {
  constructor() {
    super(HttpStatus.TOO_MANY_REQUESTS, 'LimitExceeded', 'error.Error.Auth.Session.MaxSessionsReached')
  }
}

export class MaxDevicesReachedException extends BaseApiException {
  constructor() {
    super(HttpStatus.TOO_MANY_REQUESTS, 'LimitExceeded', 'error.Error.Auth.Device.MaxDevicesReached')
  }
}

export class SessionNotFoundException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Session.NotFound')
  }
}

export class MismatchedSessionTokenException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Session.MismatchedToken', [
      { code: 'error.Error.Auth.Session.MismatchedToken', path: 'session' }
    ])
  }
}

export class DeviceNotFoundForUserException extends BaseApiException {
  constructor() {
    super(HttpStatus.NOT_FOUND, 'ResourceNotFound', 'error.Error.Auth.Device.NotFoundForUser', [
      { code: 'error.Error.Auth.Device.NotFoundForUser', path: 'deviceId' }
    ])
  }
}

export class RefreshTokenNotFoundException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Token.RefreshTokenNotFound', [
      { code: 'error.Error.Auth.Token.RefreshTokenNotFound', path: 'refreshToken' }
    ])
  }
}

export class RefreshTokenSessionInvalidException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Token.RefreshTokenSessionInvalid', [
      { code: 'error.Error.Auth.Token.RefreshTokenSessionInvalid', path: 'refreshToken' }
    ])
  }
}

export class RefreshTokenDeviceMismatchException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'Unauthenticated', 'error.Error.Auth.Token.RefreshTokenDeviceMismatch', [
      { code: 'error.Error.Auth.Token.RefreshTokenDeviceMismatch', path: 'refreshToken' }
    ])
  }
}

export class TooManyRequestsException extends BaseApiException {
  constructor(messageKey: string = 'error.Error.Global.TooManyRequests') {
    super(HttpStatus.TOO_MANY_REQUESTS, 'TooManyRequests', messageKey)
  }
}

export class MaxLoginAttemptsReachedException extends BaseApiException {
  constructor() {
    super(HttpStatus.TOO_MANY_REQUESTS, 'MaxLoginAttemptsReached', 'error.Error.Auth.Login.MaxAttemptsReached')
  }
}

export class SltContextFinalizedException extends BaseApiException {
  constructor() {
    super(HttpStatus.BAD_REQUEST, 'SltContextError', 'error.Error.Auth.SltContext.Finalized')
  }
}

export class SltContextMaxAttemptsReachedException extends BaseApiException {
  constructor() {
    super(HttpStatus.TOO_MANY_REQUESTS, 'SltContextError', 'error.Error.Auth.SltContext.MaxAttemptsReached')
  }
}

export class MaxVerificationAttemptsExceededException extends BaseApiException {
  constructor() {
    super(HttpStatus.TOO_MANY_REQUESTS, 'VerificationError', 'error.Error.Auth.Verification.MaxAttemptsExceeded')
  }
}

export class SltCookieMissingException extends BaseApiException {
  constructor() {
    super(HttpStatus.UNAUTHORIZED, 'SltCookieMissing', 'error.Error.Auth.Session.SltMissing', [
      { code: 'error.Error.Auth.Session.SltMissing', path: 'slt_token' }
    ])
  }
}

export class SltContextInvalidPurposeException extends BaseApiException {
  constructor() {
    super(HttpStatus.BAD_REQUEST, 'SltContextInvalidPurpose', 'error.Error.Auth.SltContext.InvalidPurpose', [
      { code: 'error.Error.Auth.SltContext.InvalidPurpose', path: 'slt_token' }
    ])
  }
}

export class UsernameAlreadyExistsException extends BaseApiException {
  constructor() {
    super(HttpStatus.CONFLICT, 'UsernameAlreadyExists', 'error.Error.Auth.Username.AlreadyExists', [
      { code: 'error.Error.Auth.Username.AlreadyExists', path: 'username' }
    ])
  }
}
