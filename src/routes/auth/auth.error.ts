import { HttpStatus, HttpException } from '@nestjs/common'
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
    return new ApiException(HttpStatus.CONFLICT, 'EMAIL_ALREADY_EXISTS', 'auth.Auth.Error.Email.AlreadyExists')
  }

  static PhoneNumberAlreadyExists(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'PHONE_NUMBER_TAKEN', 'auth.Auth.Error.Register.PhoneNumberTaken')
  }

  static UsernameAlreadyExists(username: string): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'USERNAME_ALREADY_EXISTS', 'auth.Auth.Error.Username.AlreadyExists', [
      { code: 'username', value: username }
    ])
  }

  static EmailAlreadyVerified(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'EMAIL_ALREADY_VERIFIED', 'auth.Auth.Error.Email.AlreadyVerified')
  }

  static InvalidPassword(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'INVALID_PASSWORD', 'auth.Auth.Error.Password.Invalid')
  }

  static AccountLocked(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'ACCOUNT_LOCKED', 'auth.Auth.Error.Account.Locked')
  }

  static AccountNotActive(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'ACCOUNT_NOT_ACTIVE', 'auth.Auth.Error.Account.NotActive')
  }

  // Token Errors
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
      HttpStatus.BAD_REQUEST,
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

  // OTP Errors
  static InvalidOTP(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'INVALID_OTP', 'auth.Auth.Error.Otp.Invalid')
  }

  static OTPExpired(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'OTP_EXPIRED', 'auth.Auth.Error.Otp.Expired')
  }

  static TooManyOTPAttempts(): ApiException {
    return new ApiException(
      HttpStatus.TOO_MANY_REQUESTS,
      'TOO_MANY_OTP_ATTEMPTS',
      'auth.Auth.Error.Otp.TooManyAttempts'
    )
  }

  static OTPSendingFailed(): ApiException {
    return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'OTP_SENDING_FAILED', 'auth.Auth.Error.Otp.FailedToSend')
  }

  static OTPSendingLimited(): ApiException {
    return new ApiException(HttpStatus.TOO_MANY_REQUESTS, 'OTP_SENDING_LIMITED', 'auth.Auth.Otp.CooldownActive')
  }

  static OTPMaxAttemptsExceeded(): HttpException {
    return new HttpException(
      {
        message: 'Quá nhiều lần thử nhập mã OTP. Vui lòng yêu cầu mã mới.',
        errorCode: 'OTP_MAX_ATTEMPTS_EXCEEDED'
      },
      HttpStatus.TOO_MANY_REQUESTS
    )
  }

  // SLT Errors
  static SLTCookieMissing(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'SLT_COOKIE_MISSING', 'auth.Auth.Error.SLT.CookieMissing')
  }

  static SLTExpired(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'SLT_EXPIRED', 'auth.Auth.Error.SLT.Expired')
  }

  static InvalidSLT(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'INVALID_SLT', 'auth.Auth.Error.SLT.Invalid')
  }

  static SLTInvalidPurpose(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'SLT_INVALID_PURPOSE', 'auth.Auth.Error.SLT.InvalidPurpose')
  }

  static EmailMissingInSltContext(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'EMAIL_MISSING_IN_SLT_CONTEXT',
      'auth.Auth.Error.Slt.EmailMissingInContext'
    )
  }

  static SLTAlreadyUsed(): HttpException {
    return new HttpException(
      {
        message: 'Token xác thực ngắn hạn đã được sử dụng. Vui lòng yêu cầu một token mới.',
        errorCode: 'SLT_ALREADY_USED'
      },
      HttpStatus.UNAUTHORIZED
    )
  }

  static SLTMaxAttemptsExceeded(): HttpException {
    return new HttpException(
      {
        message: 'Quá nhiều lần thử với token xác thực ngắn hạn. Vui lòng yêu cầu một token mới.',
        errorCode: 'SLT_MAX_ATTEMPTS_EXCEEDED'
      },
      HttpStatus.TOO_MANY_REQUESTS
    )
  }

  // 2FA Errors
  static TOTPAlreadyEnabled(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'TOTP_ALREADY_ENABLED', 'auth.Auth.Error.2FA.AlreadyEnabled')
  }

  static TOTPNotEnabled(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'TOTP_NOT_ENABLED', 'auth.Auth.Error.2FA.NotEnabled')
  }

  static InvalidTOTP(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'INVALID_TOTP', 'auth.Auth.Error.2FA.InvalidTOTP')
  }

  static SessionRevoked(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'SESSION_REVOKED', 'auth.Auth.Error.Session.RevokedRemotely')
  }

  static InvalidVerificationMethod(): HttpException {
    return new HttpException(
      {
        message: 'Phương thức xác thực không hợp lệ hoặc không được hỗ trợ.',
        errorCode: 'INVALID_VERIFICATION_METHOD'
      },
      HttpStatus.BAD_REQUEST
    )
  }

  // Session Errors
  static SessionNotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'SESSION_NOT_FOUND', 'auth.Auth.Error.Session.NotFound')
  }

  static CannotRevokeCurrent(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'SESSION_REVOKE_CURRENT',
      'auth.Auth.Error.Session.CannotRevokeCurrent'
    )
  }

  static MissingSessionIdInToken(): ApiException {
    return new ApiException(
      HttpStatus.UNAUTHORIZED,
      'SESSION_ID_MISSING',
      'auth.Auth.Error.Session.MissingSessionIdInToken'
    )
  }

  static DeviceNotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'DEVICE_NOT_FOUND', 'auth.Auth.Error.Device.NotFound')
  }

  static DeviceNotOwnedByUser(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'DEVICE_NOT_OWNED', 'auth.Auth.Error.Device.NotOwnedByUser')
  }

  static DeviceProcessingFailed(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'DEVICE_PROCESSING_FAILED',
      'auth.Auth.Error.Device.ProcessingFailed'
    )
  }

  static MissingDeviceInformation(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'MISSING_DEVICE_INFORMATION',
      'auth.Auth.Error.Device.MissingInformation'
    )
  }

  // Permission Errors
  static InsufficientPermissions(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'INSUFFICIENT_PERMISSIONS', 'auth.Auth.Error.Access.Denied')
  }

  static RoleNotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'ROLE_NOT_FOUND', 'auth.Auth.Error.Role.NotFound')
  }

  // Social Auth Errors
  static SocialAuthFailed(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'SOCIAL_AUTH_FAILED', 'auth.Auth.Error.Social.GenericAuthFailed')
  }

  static SocialEmailMismatch(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'SOCIAL_EMAIL_MISMATCH', 'auth.Auth.Error.Social.EmailMismatch')
  }

  static SocialAccountAlreadyLinked(): ApiException {
    return new ApiException(
      HttpStatus.CONFLICT,
      'SOCIAL_ACCOUNT_ALREADY_LINKED',
      'auth.Auth.Error.Social.AccountAlreadyLinked'
    )
  }

  static InvalidSocialToken(): ApiException {
    return new ApiException(
      HttpStatus.UNPROCESSABLE_ENTITY,
      'INVALID_SOCIAL_TOKEN',
      'auth.Auth.Error.Social.InvalidToken'
    )
  }

  static GoogleAccountAlreadyLinked(): ApiException {
    return new ApiException(
      HttpStatus.CONFLICT,
      'GOOGLE_ACCOUNT_ALREADY_LINKED',
      'auth.Auth.Error.Google.AccountAlreadyLinked'
    )
  }

  static GoogleUserInfoFailed(): ApiException {
    return new ApiException(
      HttpStatus.UNPROCESSABLE_ENTITY,
      'GOOGLE_USER_INFO_FAILED',
      'auth.Auth.Error.Google.UserInfoFailed'
    )
  }

  static GoogleInvalidGrant(): ApiException {
    return new ApiException(
      HttpStatus.UNPROCESSABLE_ENTITY,
      'GOOGLE_INVALID_GRANT',
      'auth.Auth.Error.Google.InvalidGrant'
    )
  }

  static GoogleMissingCode(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'GOOGLE_MISSING_CODE', 'auth.Auth.Error.Google.MissingCode')
  }

  static GoogleStateMismatch(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'GOOGLE_STATE_MISMATCH', 'auth.Auth.Error.Google.StateMismatch')
  }

  static GoogleInvalidPayload(): ApiException {
    return new ApiException(
      HttpStatus.UNPROCESSABLE_ENTITY,
      'GOOGLE_INVALID_PAYLOAD',
      'auth.Auth.Error.Google.InvalidPayload'
    )
  }

  static GoogleAccountConflict(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'GOOGLE_ACCOUNT_CONFLICT', 'auth.Auth.Error.Google.AccountConflict')
  }

  static InsufficientRevocationData(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'INSUFFICIENT_REVOCATION_DATA',
      'auth.Auth.Error.Session.InsufficientDataForRevocation'
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
      'auth.Auth.Error.Global.InternalServerError',
      details ? [{ code: 'internal_error_detail', value: details }] : undefined
    )
  }
}
