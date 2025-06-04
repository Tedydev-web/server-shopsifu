import { HttpException, HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

/**
 * Lớp tiện ích để tạo các lỗi liên quan đến xác thực
 * Thay thế cho các exceptions trong src/routes/auth/shared/exceptions/auth.exceptions.ts
 */
export class AuthError {
  // Account Errors
  static EmailNotFound(): HttpException {
    return new HttpException('Email không tồn tại', HttpStatus.NOT_FOUND)
  }

  static EmailAlreadyExists(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'EmailAlreadyExists', 'Auth.Error.Email.AlreadyExists')
  }

  static PhoneNumberAlreadyExists(): ApiException {
    return new ApiException(HttpStatus.CONFLICT, 'PhoneNumberAlreadyExists', 'Auth.Error.Register.PhoneNumberTaken')
  }

  static UsernameAlreadyExists(username: string): HttpException {
    return new HttpException(`Username ${username} đã tồn tại`, HttpStatus.CONFLICT)
  }

  static EmailAlreadyVerified(): HttpException {
    return new HttpException('Email đã được xác minh', HttpStatus.BAD_REQUEST)
  }

  static InvalidPassword(): HttpException {
    return new HttpException('Mật khẩu không đúng', HttpStatus.UNAUTHORIZED)
  }

  static AccountLocked(): HttpException {
    return new HttpException('Tài khoản đã bị khóa', HttpStatus.FORBIDDEN)
  }

  static AccountNotActive(): HttpException {
    return new HttpException('Tài khoản chưa được kích hoạt', HttpStatus.FORBIDDEN)
  }

  // Token Errors
  static InvalidAccessToken(): HttpException {
    return new HttpException('Access token không hợp lệ hoặc đã hết hạn', HttpStatus.UNAUTHORIZED)
  }

  static InvalidRefreshToken(): HttpException {
    return new HttpException('Refresh token không hợp lệ hoặc đã hết hạn', HttpStatus.UNAUTHORIZED)
  }

  static MissingRefreshToken(): HttpException {
    return new HttpException('Refresh token bị thiếu', HttpStatus.BAD_REQUEST)
  }

  static MissingAccessToken(): HttpException {
    return new HttpException('Access token bị thiếu', HttpStatus.UNAUTHORIZED)
  }

  // OTP Errors
  static InvalidOTP(): HttpException {
    return new HttpException('Mã OTP không đúng', HttpStatus.BAD_REQUEST)
  }

  static OTPExpired(): HttpException {
    return new HttpException('Mã OTP đã hết hạn', HttpStatus.BAD_REQUEST)
  }

  static TooManyOTPAttempts(): HttpException {
    return new HttpException('Quá nhiều lần nhập sai OTP', HttpStatus.TOO_MANY_REQUESTS)
  }

  static OTPSendingLimited(): HttpException {
    return new HttpException('Đã gửi quá nhiều mã OTP, vui lòng thử lại sau', HttpStatus.TOO_MANY_REQUESTS)
  }

  // SLT Errors
  static SLTCookieMissing(): HttpException {
    return new HttpException('SLT cookie bị thiếu', HttpStatus.BAD_REQUEST)
  }

  static SLTExpired(): HttpException {
    return new HttpException('SLT đã hết hạn', HttpStatus.UNAUTHORIZED)
  }

  static SLTInvalidPurpose(): HttpException {
    return new HttpException('SLT không đúng mục đích', HttpStatus.BAD_REQUEST)
  }

  // 2FA Errors
  static TOTPAlreadyEnabled(): HttpException {
    return new HttpException('2FA đã được kích hoạt', HttpStatus.BAD_REQUEST)
  }

  static TOTPNotEnabled(): HttpException {
    return new HttpException('2FA chưa được kích hoạt', HttpStatus.BAD_REQUEST)
  }

  static InvalidTOTP(): HttpException {
    return new HttpException('Mã TOTP không đúng', HttpStatus.BAD_REQUEST)
  }

  // Session Errors
  static SessionNotFound(): HttpException {
    return new HttpException('Phiên không tồn tại', HttpStatus.NOT_FOUND)
  }

  static CannotRevokeCurrent(): HttpException {
    return new ApiException(
      HttpStatus.BAD_REQUEST,
      'SESSION_REVOKE_CURRENT',
      'auth.Auth.Error.Session.CannotRevokeCurrent'
    )
  }

  static MissingSessionIdInToken(): HttpException {
    return new ApiException(
      HttpStatus.UNAUTHORIZED,
      'SESSION_ID_MISSING',
      'auth.Auth.Error.Session.MissingSessionIdInToken'
    )
  }

  static DeviceNotFound(): HttpException {
    return new ApiException(HttpStatus.NOT_FOUND, 'DEVICE_NOT_FOUND', 'auth.Auth.Error.Device.NotFound')
  }

  static DeviceNotOwnedByUser(): HttpException {
    return new HttpException('Thiết bị không thuộc về người dùng', HttpStatus.FORBIDDEN)
  }

  // Permission Errors
  static InsufficientPermissions(): HttpException {
    return new HttpException('Không đủ quyền truy cập', HttpStatus.FORBIDDEN)
  }

  static RoleNotFound(): HttpException {
    return new HttpException('Vai trò không tồn tại', HttpStatus.NOT_FOUND)
  }

  // Social Auth Errors
  static SocialAuthFailed(): HttpException {
    return new HttpException('Xác thực mạng xã hội thất bại', HttpStatus.UNAUTHORIZED)
  }

  static SocialEmailMismatch(): HttpException {
    return new HttpException('Email từ mạng xã hội không khớp', HttpStatus.BAD_REQUEST)
  }

  static SocialAccountAlreadyLinked(): HttpException {
    return new HttpException('Tài khoản mạng xã hội đã được liên kết', HttpStatus.CONFLICT)
  }

  static InvalidSocialToken(): HttpException {
    return new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, 'INVALID_SOCIAL_TOKEN', 'Auth.Error.Social.InvalidToken')
  }

  static GoogleAccountAlreadyLinked(): HttpException {
    return new ApiException(
      HttpStatus.CONFLICT,
      'GOOGLE_ACCOUNT_ALREADY_LINKED',
      'Auth.Error.Google.AccountAlreadyLinked'
    )
  }

  static GoogleUserInfoFailed(): HttpException {
    return new ApiException(
      HttpStatus.UNPROCESSABLE_ENTITY,
      'GOOGLE_USER_INFO_FAILED',
      'Auth.Error.Google.UserInfoFailed'
    )
  }

  static GoogleInvalidGrant(): HttpException {
    return new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, 'GOOGLE_INVALID_GRANT', 'Auth.Error.Google.InvalidGrant')
  }

  static GoogleMissingCode(): HttpException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'GOOGLE_MISSING_CODE', 'Auth.Error.Google.MissingCode')
  }

  static GoogleStateMismatch(): HttpException {
    return new ApiException(HttpStatus.BAD_REQUEST, 'GOOGLE_STATE_MISMATCH', 'Auth.Error.Google.StateMismatch')
  }

  static GoogleInvalidPayload(): HttpException {
    return new ApiException(
      HttpStatus.UNPROCESSABLE_ENTITY,
      'GOOGLE_INVALID_PAYLOAD',
      'Auth.Error.Google.InvalidPayload'
    )
  }

  static GoogleAccountConflict(): HttpException {
    return new ApiException(HttpStatus.CONFLICT, 'GOOGLE_ACCOUNT_CONFLICT', 'Auth.Error.Google.AccountConflict')
  }
}
