import { HttpException, HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

/**
 * Lớp tiện ích để tạo các lỗi liên quan đến xác thực
 * Thay thế cho các exceptions trong src/routes/auth/shared/exceptions/auth.exceptions.ts
 */
export class AuthError {
  // Account Errors
  static EmailNotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'EMAIL_NOT_FOUND', 'Auth.Error.Email.NotFound')
  }

  static EmailAlreadyExists(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'EMAIL_ALREADY_EXISTS', 'Auth.Error.Email.AlreadyExists')
  }

  static PhoneNumberAlreadyExists(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'PHONE_NUMBER_TAKEN', 'Auth.Error.Register.PhoneNumberTaken')
  }

  static UsernameAlreadyExists(username: string): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'USERNAME_ALREADY_EXISTS', 'Auth.Error.Username.AlreadyExists', [
      { code: 'username', value: username }
    ])
  }

  static EmailAlreadyVerified(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'EMAIL_ALREADY_VERIFIED', 'Auth.Error.Email.AlreadyVerified')
  }

  static InvalidPassword(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'INVALID_PASSWORD', 'Auth.Error.Password.Invalid')
  }

  static AccountLocked(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'ACCOUNT_LOCKED', 'Auth.Error.Account.Locked')
  }

  static AccountNotActive(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'ACCOUNT_NOT_ACTIVE', 'Auth.Error.Account.NotActive')
  }

  // Token Errors
  static InvalidAccessToken(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'INVALID_ACCESS_TOKEN', 'Auth.Error.Token.InvalidAccessToken')
  }

  static InvalidRefreshToken(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'INVALID_REFRESH_TOKEN', 'Auth.Error.Token.InvalidRefreshToken')
  }

  static MissingRefreshToken(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'MISSING_REFRESH_TOKEN', 'Auth.Error.Token.MissingRefreshToken')
  }

  static MissingAccessToken(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'MISSING_ACCESS_TOKEN', 'Auth.Error.Token.MissingAccessToken')
  }

  // OTP Errors
  static InvalidOTP(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'INVALID_OTP', 'Auth.Error.Otp.Invalid')
  }

  static OTPExpired(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'OTP_EXPIRED', 'Auth.Error.Otp.Expired')
  }

  static TooManyOTPAttempts(): ApiException {
    return new ApiException(HttpStatus.TOO_MANY_REQUESTS, 'TOO_MANY_OTP_ATTEMPTS', 'Auth.Error.Otp.TooManyAttempts')
  }

  static OTPSendingLimited(): ApiException {
    return new ApiException(HttpStatus.TOO_MANY_REQUESTS, 'OTP_SENDING_LIMITED', 'Auth.Otp.CooldownActive')
  }

  // SLT Errors
  static SLTCookieMissing(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'SLT_COOKIE_MISSING', 'Auth.Error.SLT.CookieMissing')
  }

  static SLTExpired(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'SLT_EXPIRED', 'Auth.Error.SLT.Expired')
  }

  static SLTInvalidPurpose(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'SLT_INVALID_PURPOSE', 'Auth.Error.SLT.InvalidPurpose')
  }

  static EmailMissingInSltContext(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'EMAIL_MISSING_IN_SLT_CONTEXT',
      'Auth.Error.Slt.EmailMissingInContext'
    )
  }

  // 2FA Errors
  static TOTPAlreadyEnabled(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'TOTP_ALREADY_ENABLED', 'Auth.Error.2FA.AlreadyEnabled')
  }

  static TOTPNotEnabled(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'TOTP_NOT_ENABLED', 'Auth.Error.2FA.NotEnabled')
  }

  static InvalidTOTP(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'INVALID_TOTP', 'Auth.Error.2FA.InvalidTOTP')
  }

  // Session Errors
  static SessionNotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'SESSION_NOT_FOUND', 'Auth.Error.Session.NotFound')
  }

  static CannotRevokeCurrent(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'SESSION_REVOKE_CURRENT', 'Auth.Error.Session.CannotRevokeCurrent')
  }

  static MissingSessionIdInToken(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'SESSION_ID_MISSING', 'Auth.Error.Session.MissingSessionIdInToken')
  }

  static DeviceNotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'DEVICE_NOT_FOUND', 'Auth.Error.Device.NotFound')
  }

  static DeviceNotOwnedByUser(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'DEVICE_NOT_OWNED', 'Auth.Device.NotOwnedByUser')
  }

  // Permission Errors
  static InsufficientPermissions(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'INSUFFICIENT_PERMISSIONS', 'Auth.Error.Access.Denied')
  }

  static RoleNotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'ROLE_NOT_FOUND', 'Error.Role.NotFound')
  }

  // Social Auth Errors
  static SocialAuthFailed(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'SOCIAL_AUTH_FAILED', 'Auth.Error.Social.GenericAuthFailed')
  }

  static SocialEmailMismatch(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'SOCIAL_EMAIL_MISMATCH', 'Auth.Error.Social.EmailMismatch')
  }

  static SocialAccountAlreadyLinked(): ApiException {
    return new ApiException(
      HttpStatus.CONFLICT,
      'SOCIAL_ACCOUNT_ALREADY_LINKED',
      'Auth.Error.Social.AccountAlreadyLinked'
    )
  }

  static InvalidSocialToken(): ApiException {
    return new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, 'INVALID_SOCIAL_TOKEN', 'Auth.Error.Social.InvalidToken')
  }

  static GoogleAccountAlreadyLinked(): ApiException {
    return new ApiException(
      HttpStatus.CONFLICT,
      'GOOGLE_ACCOUNT_ALREADY_LINKED',
      'Auth.Error.Google.AccountAlreadyLinked'
    )
  }

  static GoogleUserInfoFailed(): ApiException {
    return new ApiException(
      HttpStatus.UNPROCESSABLE_ENTITY,
      'GOOGLE_USER_INFO_FAILED',
      'Auth.Error.Google.UserInfoFailed'
    )
  }

  static GoogleInvalidGrant(): ApiException {
    return new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, 'GOOGLE_INVALID_GRANT', 'Auth.Error.Google.InvalidGrant')
  }

  static GoogleMissingCode(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'GOOGLE_MISSING_CODE', 'Auth.Error.Google.MissingCode')
  }

  static GoogleStateMismatch(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'GOOGLE_STATE_MISMATCH', 'Auth.Error.Google.StateMismatch')
  }

  static GoogleInvalidPayload(): ApiException {
    return new ApiException(
      HttpStatus.UNPROCESSABLE_ENTITY,
      'GOOGLE_INVALID_PAYLOAD',
      'Auth.Error.Google.InvalidPayload'
    )
  }

  static GoogleAccountConflict(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'GOOGLE_ACCOUNT_CONFLICT', 'auth.Auth.Error.Google.AccountConflict')
  }

  static InsufficientRevocationData(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'INSUFFICIENT_REVOCATION_DATA',
      'Auth.Error.Session.InsufficientDataForRevocation'
    )
  }

  static InvalidRecoveryCode(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'INVALID_RECOVERY_CODE', 'auth.Auth.Error.2FA.InvalidRecoveryCode')
  }

  static InvalidTwoFactorMethod(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'INVALID_2FA_METHOD', 'auth.Auth.Error.2FA.InvalidMethod')
  }

  // Global/Fallback Error
  static InternalServerError(details?: string): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'INTERNAL_SERVER_ERROR',
      'Error.Global.InternalServerError',
      details ? [{ code: 'internal_error_detail', value: details }] : undefined
    )
  }
}
