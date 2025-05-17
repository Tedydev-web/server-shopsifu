import { HttpStatus } from '@nestjs/common'
import { ApiException } from 'src/shared/exceptions/api.exception'

// OTP related errors
export const InvalidOTPException = new ApiException(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'VALIDATION_ERROR',
  'Error.Auth.Otp.Invalid',
  [{ code: 'Error.Auth.Otp.Invalid', path: 'code' }]
)

export const OTPExpiredException = new ApiException(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'VALIDATION_ERROR',
  'Error.Auth.Otp.Expired',
  [{ code: 'Error.Auth.Otp.Expired', path: 'code' }]
)

export const FailedToSendOTPException = new ApiException(
  HttpStatus.INTERNAL_SERVER_ERROR, // Hoặc SERVICE_UNAVAILABLE nếu là lỗi dịch vụ bên ngoài
  'OTP_SERVICE_ERROR',
  'Error.Auth.Otp.FailedToSend'
)

// Email related errors
export const EmailAlreadyExistsException = new ApiException(
  HttpStatus.CONFLICT, // CONFLICT (409) phù hợp hơn UNPROCESSABLE_ENTITY (422) cho việc đã tồn tại
  'VALIDATION_ERROR', // Hoặc 'RESOURCE_CONFLICT'
  'Error.Auth.Email.AlreadyExists',
  [{ code: 'Error.Auth.Email.AlreadyExists', path: 'email' }]
)

export const EmailNotFoundException = new ApiException(
  HttpStatus.NOT_FOUND,
  'RESOURCE_NOT_FOUND',
  'Error.Auth.Email.NotFound',
  [{ code: 'Error.Auth.Email.NotFound', path: 'email' }]
)

// Password related errors
export const InvalidPasswordException = new ApiException(
  HttpStatus.UNAUTHORIZED, // Unauthorized (401) khi sai pass thường hợp lý hơn
  'AUTHENTICATION_FAILURE',
  'Error.Auth.Password.Invalid',
  [{ code: 'Error.Auth.Password.Invalid', path: 'password' }]
)

// Auth token related errors
export const RefreshTokenAlreadyUsedException = new ApiException(
  HttpStatus.UNAUTHORIZED,
  'AUTHENTICATION_FAILURE',
  'Error.Auth.Token.RefreshTokenAlreadyUsed'
)

export const UnauthorizedAccessException = new ApiException(
  HttpStatus.UNAUTHORIZED,
  'UNAUTHENTICATED',
  'Error.Auth.Access.Unauthorized'
)

export const InvalidLoginSessionException = new ApiException(
  HttpStatus.UNAUTHORIZED,
  'AUTHENTICATION_FAILURE',
  'Error.Auth.Session.InvalidLogin'
)

// Cookie related errors
export const MissingAccessTokenException = new ApiException(
  HttpStatus.UNAUTHORIZED,
  'UNAUTHENTICATED',
  'Error.Auth.Token.MissingAccessToken'
)

export const InvalidAccessTokenException = new ApiException(
  HttpStatus.UNAUTHORIZED,
  'UNAUTHENTICATED',
  'Error.Auth.Token.InvalidAccessToken'
)

export const ExpiredAccessTokenException = new ApiException(
  HttpStatus.UNAUTHORIZED,
  'UNAUTHENTICATED',
  'Error.Auth.Token.ExpiredAccessToken'
)

export const MissingRefreshTokenException = new ApiException(
  HttpStatus.BAD_REQUEST, // Thiếu RT trong body/cookie là Bad Request từ client
  'BAD_REQUEST',
  'Error.Auth.Token.MissingRefreshToken'
)

// Google auth related errors
export const GoogleUserInfoException = new ApiException(
  HttpStatus.INTERNAL_SERVER_ERROR,
  'EXTERNAL_SERVICE_ERROR',
  'Error.Auth.Google.UserInfoFailed'
)

export const InvalidTOTPException = new ApiException(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'VALIDATION_ERROR',
  'Error.Auth.2FA.InvalidTOTP',
  [{ code: 'Error.Auth.2FA.InvalidTOTP', path: 'totpCode' }] // Giả sử `totpCode` là path
)

export const TOTPAlreadyEnabledException = new ApiException(
  HttpStatus.CONFLICT,
  'STATE_CONFLICT',
  'Error.Auth.2FA.AlreadyEnabled'
)

export const TOTPNotEnabledException = new ApiException(
  HttpStatus.BAD_REQUEST, // Yêu cầu hành động 2FA khi chưa bật
  'PRECONDITION_FAILED',
  'Error.Auth.2FA.NotEnabled'
)

export const InvalidRecoveryCodeException = new ApiException(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'VALIDATION_ERROR',
  'Error.Auth.2FA.InvalidRecoveryCode',
  [{ code: 'Error.Auth.2FA.InvalidRecoveryCode', path: 'code' }] // Giả sử `code` là path
)

// OtpToken related errors
export const InvalidOTPTokenException = new ApiException(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'VALIDATION_ERROR',
  'Error.Auth.OtpToken.Invalid',
  [{ code: 'Error.Auth.OtpToken.Invalid', path: 'otpToken' }]
)

export const OTPTokenExpiredException = new ApiException(
  HttpStatus.UNPROCESSABLE_ENTITY,
  'VALIDATION_ERROR',
  'Error.Auth.OtpToken.Expired',
  [{ code: 'Error.Auth.OtpToken.Expired', path: 'otpToken' }]
)

export const InvalidDeviceException = new ApiException(
  HttpStatus.UNAUTHORIZED, // Hoặc FORBIDDEN nếu đã xác thực nhưng thiết bị không hợp lệ
  'AUTHENTICATION_FAILURE', // Hoặc 'DEVICE_ERROR'
  'Error.Auth.Device.Invalid'
)

export const DeviceMismatchException = new ApiException(
  HttpStatus.UNAUTHORIZED, // Nghi ngờ chiếm đoạt session
  'AUTHENTICATION_FAILURE',
  'Error.Auth.Device.Mismatch'
  // [{ code: 'Error.Auth.Device.Mismatch', path: 'device' }] // path có thể không rõ ràng ở đây
)
