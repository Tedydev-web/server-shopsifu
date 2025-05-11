import { UnauthorizedException, UnprocessableEntityException } from '@nestjs/common'

// OTP related errors
export const InvalidOTPException = new UnprocessableEntityException([
  {
    message: 'Error.InvalidOTP',
    path: 'code'
  }
])

export const OTPExpiredException = new UnprocessableEntityException([
  {
    message: 'Error.OTPExpired',
    path: 'code'
  }
])

export const TooManyAttemptsException = new UnprocessableEntityException([
  {
    message: 'Error.TooManyAttempts',
    path: 'code'
  }
])

export const FailedToSendOTPException = new UnprocessableEntityException([
  {
    message: 'Error.FailedToSendOTP',
    path: 'code'
  }
])

// Email related errors
export const EmailAlreadyExistsException = new UnprocessableEntityException([
  {
    message: 'Error.EmailAlreadyExists',
    path: 'email'
  }
])

export const EmailNotFoundException = new UnprocessableEntityException([
  {
    message: 'Error.EmailNotFound',
    path: 'email'
  }
])

// Password related errors
export const InvalidPasswordException = new UnprocessableEntityException([
  {
    message: 'Error.InvalidPassword',
    path: 'password'
  }
])

export const PasswordMismatchException = new UnprocessableEntityException([
  {
    message: 'Error.PasswordMismatch',
    path: 'confirmPassword'
  }
])

export const PasswordRequirementsException = new UnprocessableEntityException([
  {
    message: 'Error.PasswordRequirements',
    path: 'password'
  }
])

// Auth token related errors
export const RefreshTokenAlreadyUsedException = new UnauthorizedException([
  {
    message: 'Error.RefreshTokenAlreadyUsed',
    path: 'refreshToken'
  }
])

export const UnauthorizedAccessException = new UnauthorizedException([
  {
    message: 'Error.UnauthorizedAccess',
    path: 'token'
  }
])

// Otp token related errors
export const OtpTokenExpiredException = new UnauthorizedException([
  {
    message: 'Error.OtpTokenExpired',
    path: 'token'
  }
])

export const InvalidOtpTokenException = new UnauthorizedException([
  {
    message: 'Error.InvalidOtpToken',
    path: 'token'
  }
])

export const OtpTokenAlreadyUsedException = new UnauthorizedException([
  {
    message: 'Error.OtpTokenAlreadyUsed',
    path: 'token'
  }
])

export const InvalidOtpTokenTypeException = new UnauthorizedException([
  {
    message: 'Error.InvalidOtpTokenType',
    path: 'token'
  }
])

// Google auth related errors
export const GoogleUserInfoError = new Error('Error.FailedToGetGoogleUserInfo')

// Generic response messages
export const SuccessMessages = {
  OTP_SENT: 'Gửi mã OTP thành công',
  PASSWORD_RESET: 'Đổi mật khẩu thành công',
  LOGOUT: 'Đăng xuất thành công'
}
