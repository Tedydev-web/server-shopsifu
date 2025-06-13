import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

export class AuthError {
  public static ServiceNotAvailable(serviceName: string): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'AUTH_SERVICE_UNAVAILABLE',
      'auth.error.serviceUnavailable',
      { serviceName }
    )
  }

  public static InternalServerError(details?: any): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'AUTH_INTERNAL_SERVER_ERROR',
      'global.general.error.internalServerError',
      details
    )
  }

  public static SLTCookieMissing(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_SLT_COOKIE_MISSING', 'auth.error.sltCookieMissing')
  }

  public static InvalidPassword(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'AUTH_INVALID_PASSWORD', 'auth.error.invalidPassword')
  }

  public static PasswordsNotMatch(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_PASSWORDS_NOT_MATCH', 'auth.error.passwordsNotMatch')
  }

  public static UsernameAlreadyExists(username: string): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'AUTH_USERNAME_EXISTS', 'auth.error.usernameExists', { username })
  }

  public static EmailAlreadyExists(email?: string): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'AUTH_EMAIL_EXISTS', 'auth.error.emailExists', { email })
  }

  public static EmailNotFound(email?: string): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'AUTH_EMAIL_NOT_FOUND', 'auth.error.emailNotFound', { email })
  }

  public static DeviceProcessingFailed(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'AUTH_DEVICE_PROCESSING_FAILED',
      'auth.error.deviceProcessingFailed'
    )
  }

  public static DeviceNotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'AUTH_DEVICE_NOT_FOUND', 'auth.error.deviceNotFound')
  }

  public static InvalidRefreshToken(): ApiException {
    return new ApiException(
      HttpStatus.UNAUTHORIZED,
      'AUTH_INVALID_REFRESH_TOKEN',
      'auth.error.token.invalidRefreshToken'
    )
  }

  public static MissingRefreshToken(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_MISSING_REFRESH_TOKEN', 'auth.error.missingRefreshToken')
  }

  public static InsufficientPermissions(): ApiException {
    return new ApiException(HttpStatus.FORBIDDEN, 'AUTH_INSUFFICIENT_PERMISSIONS', 'auth.error.insufficientPermissions')
  }

  public static EmailMissingInSltContext(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'AUTH_EMAIL_MISSING_IN_CONTEXT',
      'auth.error.emailMissingInSltContext'
    )
  }

  public static InvalidOTP(canRetry: boolean = true): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_INVALID_OTP', 'auth.error.invalidOtp', {
      canRetry,
      field: 'code'
    })
  }

  public static OTPSendingFailed(): ApiException {
    return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'AUTH_OTP_SENDING_FAILED', 'auth.error.otpSendingFailed')
  }

  public static TooManyOTPAttempts(): ApiException {
    return new ApiException(HttpStatus.TOO_MANY_REQUESTS, 'AUTH_TOO_MANY_OTP_ATTEMPTS', 'auth.error.tooManyOtpAttempts')
  }

  public static OTPExpired(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_OTP_EXPIRED', 'auth.error.otpExpired')
  }

  public static InvalidPageOrLimit(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_INVALID_PAGE_OR_LIMIT', 'auth.error.invalidPageOrLimit')
  }

  public static SessionsNotFound(): ApiException {
    return new ApiException(HttpStatus.NOT_FOUND, 'AUTH_SESSIONS_NOT_FOUND', 'auth.error.sessionsNotFound')
  }

  public static InvalidRevokeParams(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_INVALID_REVOKE_PARAMS', 'auth.error.invalidRevokeParams')
  }

  public static EmailRequired(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_EMAIL_REQUIRED', 'auth.error.emailRequired')
  }

  public static SessionOrDeviceNotFound(): ApiException {
    return new ApiException(
      HttpStatus.NOT_FOUND,
      'AUTH_SESSION_OR_DEVICE_NOT_FOUND',
      'auth.error.sessionOrDeviceNotFound'
    )
  }

  public static InvalidDeviceId(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_INVALID_DEVICE_ID', 'auth.error.invalidDeviceId')
  }

  public static InvalidDeviceName(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_INVALID_DEVICE_NAME', 'auth.error.invalidDeviceName')
  }

  public static MissingNewPasswordInContext(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'AUTH_MISSING_NEW_PASSWORD_IN_CONTEXT',
      'auth.error.missingNewPasswordInContext'
    )
  }

  public static PasswordChangeNotAllowed(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'AUTH_PASSWORD_CHANGE_NOT_ALLOWED',
      'auth.error.passwordChangeNotAllowed'
    )
  }

  // --- Social Login Errors ---

  public static GoogleCallbackError(details?: any): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'AUTH_GOOGLE_CALLBACK_ERROR',
      'auth.error.social.googleCallbackError',
      details
    )
  }

  public static PendingSocialLinkTokenMissing(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'AUTH_PENDING_LINK_TOKEN_MISSING',
      'auth.error.social.pendingLinkTokenMissing'
    )
  }

  public static GoogleLinkFailed(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'AUTH_GOOGLE_LINK_FAILED',
      'auth.error.social.googleLinkFailed'
    )
  }

  public static GoogleAccountAlreadyLinked(): ApiException {
    return new ApiException(
      HttpStatus.CONFLICT,
      'AUTH_GOOGLE_ACCOUNT_ALREADY_LINKED',
      'auth.error.social.googleAccountAlreadyLinked'
    )
  }

  public static InvalidSocialToken(): ApiException {
    return new ApiException(
      HttpStatus.UNAUTHORIZED,
      'AUTH_INVALID_SOCIAL_TOKEN',
      'auth.error.social.invalidSocialToken'
    )
  }

  public static GoogleMissingCode(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_GOOGLE_MISSING_CODE', 'auth.error.social.googleMissingCode')
  }

  public static GoogleInvalidPayload(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'AUTH_GOOGLE_INVALID_PAYLOAD',
      'auth.error.social.googleInvalidPayload'
    )
  }

  public static GoogleUserInfoFailed(): ApiException {
    return new ApiException(
      HttpStatus.INTERNAL_SERVER_ERROR,
      'AUTH_GOOGLE_USER_INFO_FAILED',
      'auth.error.social.googleUserInfoFailed'
    )
  }

  // --- Two-Factor Authentication Errors ---

  public static TOTPAlreadyEnabled(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'AUTH_2FA_ALREADY_ENABLED', 'auth.error.2fa.alreadyEnabled')
  }

  public static InvalidTOTP(canRetry: boolean = true): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_2FA_INVALID_TOTP', 'auth.error.2fa.invalidOtp', {
      canRetry,
      field: 'code'
    })
  }

  public static TOTPNotEnabled(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_2FA_NOT_ENABLED', 'auth.error.2fa.notEnabled')
  }

  public static InvalidRecoveryCode(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'AUTH_2FA_INVALID_RECOVERY_CODE',
      'auth.error.2fa.invalidRecoveryCode'
    )
  }

  public static InvalidVerificationMethod(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'AUTH_2FA_INVALID_VERIFICATION_METHOD',
      'auth.error.2fa.invalidVerificationMethod'
    )
  }

  // --- Short-Lived Token (SLT) Errors ---

  public static SLTInvalidPurpose(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_SLT_INVALID_PURPOSE', 'auth.error.slt.invalidPurpose')
  }

  public static SLTExpired(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_SLT_EXPIRED', 'auth.error.slt.expired')
  }

  public static SLTAlreadyUsed(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'AUTH_SLT_ALREADY_USED', 'auth.error.slt.alreadyUsed')
  }

  public static SLTMaxAttemptsExceeded(): ApiException {
    return new ApiException(HttpStatus.TOO_MANY_REQUESTS, 'AUTH_SLT_MAX_ATTEMPTS', 'auth.error.slt.maxAttemptsExceeded')
  }

  // --- Pending Link Token Errors ---

  public static InvalidPendingLinkToken(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_PENDING_LINK_TOKEN_INVALID', 'auth.error.pendingLink.invalid')
  }

  // --- Token Errors ---

  public static InvalidAccessToken(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'AUTH_ACCESS_TOKEN_INVALID', 'auth.error.token.invalidAccessToken')
  }

  public static RefreshTokenExpired(): ApiException {
    return new ApiException(
      HttpStatus.UNAUTHORIZED,
      'AUTH_REFRESH_TOKEN_EXPIRED',
      'auth.error.token.refreshTokenExpired'
    )
  }

  public static AccessTokenExpired(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'AUTH_ACCESS_TOKEN_EXPIRED', 'auth.error.token.accessTokenExpired')
  }

  public static MissingAccessToken(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'AUTH_MISSING_ACCESS_TOKEN', 'auth.error.token.missingAccessToken')
  }

  public static MissingSessionIdInToken(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'AUTH_MISSING_SESSION_ID', 'auth.error.token.missingSessionId')
  }

  // --- Session Errors ---
  public static SessionRevoked(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'AUTH_SESSION_REVOKED', 'auth.error.session.revoked')
  }

  // --- General Auth Errors ---
  public static Unauthorized(message?: string, details?: any): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'AUTH_UNAUTHORIZED', message || 'auth.error.unauthorized', details)
  }

  public static InvalidCredentials(errorType: 'email' | 'password', details?: any): ApiException {
    if (errorType === 'email') {
      return new ApiException(HttpStatus.UNAUTHORIZED, 'AUTH_EMAIL_NOT_FOUND', 'auth.error.emailNotFound', details)
    } else {
      return new ApiException(
        HttpStatus.UNAUTHORIZED,
        'AUTH_INCORRECT_PASSWORD',
        'auth.error.incorrectPassword',
        details
      )
    }
  }

  public static AccountLocked(): ApiException {
    return new ApiException(HttpStatus.UNAUTHORIZED, 'AUTH_ACCOUNT_LOCKED', 'auth.error.accountLocked')
  }

  // --- Login Validation Errors (400) ---

  public static InvalidLoginCredentials(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_INVALID_LOGIN_CREDENTIALS', 'auth.error.invalidCredentials')
  }

  public static InvalidEmailFormat(): ApiException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'AUTH_INVALID_EMAIL_FORMAT',
      'auth.error.validation.invalidEmailFormat'
    )
  }

  public static PasswordTooShort(): ApiException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'AUTH_PASSWORD_TOO_SHORT', 'auth.error.validation.passwordTooShort')
  }

  // --- Verification Errors (400 vs 401) ---

  public static InvalidVerificationCode(canRetry: boolean = true): ApiException {
    return new ApiException(
      canRetry ? HttpStatus.BAD_REQUEST : HttpStatus.UNAUTHORIZED,
      'AUTH_INVALID_VERIFICATION_CODE',
      'auth.error.verification.invalidCode',
      { canRetry, field: 'code' }
    )
  }

  public static VerificationSessionExpired(): ApiException {
    return new ApiException(
      HttpStatus.UNAUTHORIZED,
      'AUTH_VERIFICATION_SESSION_EXPIRED',
      'auth.error.verification.sessionExpired'
    )
  }
}
