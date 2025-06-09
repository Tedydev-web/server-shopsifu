import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'
export class AuthError {
  // Lỗi liên quan đến User/Email/Password
  static EmailNotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'EMAIL_NOT_FOUND', 'auth.Auth.Error.Email.NotFound')
  }

  static EmailAlreadyExists(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'EMAIL_ALREADY_EXISTS', 'auth.Auth.Error.Email.AlreadyExists')
  }

  static PhoneNumberAlreadyExists(): ApiException {
    return new ApiException(
      HttpStatus.CONFLICT,
      'PHONE_NUMBER_ALREADY_EXISTS',
      'auth.Auth.Error.Register.PhoneNumberTaken'
    )
  }

  static UsernameAlreadyExists(username: string): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'USERNAME_ALREADY_EXISTS', 'auth.Auth.Error.Username.AlreadyExists', [
      {
        field: 'username',
        message: 'errors.details.auth.usernameAlreadyExists', // Cần tạo i18n key này
        value: username,
        args: { username }
      }
    ])
  }

  static InvalidPassword(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'INVALID_PASSWORD', 'auth.Auth.Error.Password.Invalid', [
      {
        field: 'password',
        message: 'errors.details.auth.invalidPassword',
        value: 'password'
      }
    ])
  }

  static AccountLocked(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'ACCOUNT_LOCKED', 'auth.Auth.Error.Access.Denied')
  }

  static AccountNotActive(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'ACCOUNT_NOT_ACTIVE', 'auth.Auth.Error.Access.Denied')
  }

  // Lỗi liên quan đến Token (Access, Refresh)
  static InvalidAccessToken(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'INVALID_ACCESS_TOKEN', 'auth.Auth.Error.Token.InvalidAccessToken')
  }

  static InvalidRefreshToken(): ApiException {
    return new ApiException(
      HttpStatus.UNAUTHORIZED,
      'INVALID_REFRESH_TOKEN',
      'auth.Auth.Error.Token.InvalidRefreshToken'
    )
  }

  static MissingRefreshToken(): ApiException {
    return new ApiException(
      HttpStatus.UNAUTHORIZED,
      'MISSING_REFRESH_TOKEN',
      'auth.Auth.Error.Token.MissingRefreshToken'
    )
  }

  static MissingAccessToken(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'MISSING_ACCESS_TOKEN', 'auth.Auth.Error.Token.MissingAccessToken')
  }

  static AccessTokenExpired(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'ACCESS_TOKEN_EXPIRED', 'auth.Auth.Error.Token.ExpiredAccessToken')
  }

  static RefreshTokenExpired(): ApiException {
    return new ApiException(
      HttpStatus.UNAUTHORIZED,
      'REFRESH_TOKEN_EXPIRED',
      'auth.Auth.Error.Token.ExpiredRefreshToken'
    )
  }

  static RefreshTokenUsed(): ApiException {
    return new ApiException(
      HttpStatus.UNAUTHORIZED,
      'REFRESH_TOKEN_ALREADY_USED',
      'auth.Auth.Error.Token.RefreshTokenUsed'
    )
  }

  // Lỗi liên quan đến OTP
  static InvalidOTP(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'INVALID_OTP', 'auth.Auth.Error.Otp.Invalid')
  }

  static OTPExpired(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'OTP_EXPIRED', 'auth.Auth.Error.Otp.Expired')
  }

  static TooManyOTPAttempts(): ApiException {
    return new ApiException(HttpStatus.TOO_MANY_REQUESTS, 'TOO_MANY_OTP_ATTEMPTS', 'auth.Auth.Error.Otp.MaxAttempts')
  }

  static OTPSendingFailed(): ApiException {
    return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'OTP_SENDING_FAILED', 'auth.Auth.Error.Otp.SendingFailed')
  }

  static OtpForPasswordResetNotVerified(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'OTP_PASSWORD_RESET_NOT_VERIFIED',
      'auth.Auth.Error.Otp.PasswordResetNotVerified'
    )
  }

  // Lỗi liên quan đến SLT (Short-Lived Token)
  static SLTCookieMissing(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'SLT_COOKIE_MISSING', 'auth.Auth.Error.SLT.CookieMissing')
  }

  static SLTExpired(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'SLT_EXPIRED', 'auth.Auth.Error.SLT.Expired')
  }

  static InvalidSLT(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'INVALID_SLT', 'auth.Auth.Error.SLT.Invalid')
  }

  static SLTInvalidPurpose(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'SLT_INVALID_PURPOSE', 'auth.Auth.Error.SLT.InvalidPurpose')
  }

  static EmailMissingInSltContext(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'EMAIL_MISSING_IN_SLT_CONTEXT',
      'auth.Auth.Error.SLT.EmailMissingInContext'
    )
  }

  static SLTMaxAttemptsExceeded(): ApiException {
    return new ApiException(
      HttpStatus.TOO_MANY_REQUESTS,
      'SLT_MAX_ATTEMPTS_EXCEEDED',
      'auth.Auth.Error.SLT.MaxAttemptsExceeded'
    )
  }

  static SLTAlreadyUsed(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'SLT_ALREADY_USED', 'auth.Auth.Error.SLT.AlreadyUsed')
  }

  // Lỗi 2FA
  static TOTPAlreadyEnabled(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'TOTP_ALREADY_ENABLED', 'auth.Auth.Error.2FA.AlreadyEnabled')
  }

  static TOTPNotEnabled(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'TOTP_NOT_ENABLED', 'auth.Auth.Error.2FA.NotEnabled')
  }

  static InvalidTOTP(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'INVALID_TOTP', 'auth.Auth.Error.2FA.InvalidCode')
  }

  static InvalidRecoveryCode(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'INVALID_RECOVERY_CODE', 'auth.Auth.Error.2FA.InvalidRecoveryCode')
  }

  static TwoFactorConfigurationError(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'TWO_FACTOR_CONFIGURATION_ERROR',
      'auth.Auth.Error.2FA.ConfigurationError'
    )
  }

  static TwoFactorSetupMissingSecret(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'TWO_FACTOR_SETUP_MISSING_SECRET',
      'auth.Auth.Error.2FA.SetupMissingSecret'
    )
  }

  static InvalidVerificationMethod(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'INVALID_VERIFICATION_METHOD',
      'auth.Auth.Error.Verification.InvalidMethod'
    )
  }

  // Lỗi Session
  static SessionRevoked(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'SESSION_REVOKED', 'auth.Auth.Error.Session.Revoked')
  }

  static SessionNotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'SESSION_NOT_FOUND', 'auth.Auth.Error.Session.NotFound')
  }

  static CannotRevokeCurrent(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'CANNOT_REVOKE_CURRENT_SESSION',
      'auth.Auth.Error.Session.CannotRevokeCurrent'
    )
  }

  static MissingSessionIdInToken(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'MISSING_SESSION_ID_IN_TOKEN',
      'auth.Auth.Error.Token.MissingSessionId'
    )
  }

  // Lỗi Device
  static DeviceNotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'DEVICE_NOT_FOUND', 'auth.Auth.Error.Device.NotFound')
  }

  static DeviceNotOwnedByUser(): ApiException {
    return new ApiException(
      HttpStatus.FORBIDDEN,
      'DEVICE_NOT_OWNED_BY_USER',
      'errors.titles.auth.deviceNotOwnedByUser',
      'auth.Auth.Device.NotOwnedByUser'
    )
  }

  static DeviceProcessingFailed(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'DEVICE_PROCESSING_FAILED',
      'errors.titles.auth.deviceProcessingFailed',
      'auth.Auth.Device.ProcessingFailed'
    )
  }

  static MissingDeviceInformation(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'MISSING_DEVICE_INFORMATION',
      'errors.titles.auth.missingDeviceInformation',
      'auth.Auth.Device.MissingInformation'
    )
  }

  // Lỗi phân quyền và chung
  static InsufficientPermissions(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'INSUFFICIENT_PERMISSIONS', 'global.error.http.forbidden')
  }

  static InsufficientRevocationData(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'INSUFFICIENT_REVOCATION_DATA',
      'auth.Auth.Error.Session.InsufficientDataForRevocation'
    )
  }

  // Lỗi Social Login
  static GoogleUserInfoFailed(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'GOOGLE_USER_INFO_FAILED',
      'auth.Auth.Error.Google.UserInfoFailed'
    )
  }

  static GoogleCallbackError(details: string): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'GOOGLE_CALLBACK_ERROR',
      'auth.Auth.Error.Google.CallbackErrorGeneric',
      [
        {
          message: 'errors.details.auth.googleCallbackError', // Cần tạo i18n key này
          args: { details }
        }
      ]
    )
  }

  static GoogleMissingCode(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'GOOGLE_MISSING_CODE', 'auth.Auth.Error.Google.MissingCode')
  }

  static InvalidSocialToken(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'INVALID_SOCIAL_TOKEN', 'auth.Auth.Error.Social.InvalidToken')
  }

  static GoogleInvalidPayload(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'GOOGLE_INVALID_PAYLOAD', 'auth.Auth.Error.Google.InvalidPayload')
  }

  static GoogleAccountConflict(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'GOOGLE_ACCOUNT_CONFLICT', 'auth.Auth.Error.Google.AccountConflict')
  }

  static GoogleAccountAlreadyLinked(): ApiException {
    return new ApiException(
      HttpStatus.CONFLICT,
      'GOOGLE_ACCOUNT_ALREADY_LINKED',
      'auth.Auth.Error.Google.AlreadyLinkedToOtherGoogle'
    )
  }

  static GoogleLinkFailed(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'GOOGLE_LINK_FAILED',
      'auth.Auth.Error.Google.LinkAccountFailed'
    )
  }

  static PendingSocialLinkTokenMissing(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'PENDING_SOCIAL_LINK_TOKEN_MISSING',
      'auth.Auth.Error.Google.Link.NoPendingState'
    )
  }

  // Lỗi chung
  static InternalServerError(message?: string): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'INTERNAL_SERVER_ERROR',
      message ?? 'global.error.general.internalServerError'
    )
  }

  static BadRequest(message?: string): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'BAD_REQUEST', message ?? 'global.error.http.badRequest')
  }

  static Unauthorized(message?: string): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'UNAUTHORIZED', message ?? 'global.error.http.unauthorized')
  }

  static VerificationFailed(details?: any[]): ApiException {
    // Chú ý: signature đã thay đổi
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'VERIFICATION_FAILED',
      'auth.Auth.Error.Verification.Failed',
      details
    )
  }
}
