import { UnauthorizedException, UnprocessableEntityException } from '@nestjs/common'

// =========== Error Messages ===========
export const PasswordErrorMessages = {
  MIN_LENGTH: 'Mật khẩu phải có ít nhất 8 ký tự',
  MAX_LENGTH: 'Mật khẩu không được vượt quá 100 ký tự',
  UPPERCASE: 'Mật khẩu phải chứa ít nhất 1 chữ hoa',
  LOWERCASE: 'Mật khẩu phải chứa ít nhất 1 chữ thường',
  NUMBER: 'Mật khẩu phải chứa ít nhất 1 số',
  SPECIAL_CHAR: 'Mật khẩu phải chứa ít nhất 1 ký tự đặc biệt',
  MATCH: 'Mật khẩu và mật khẩu xác nhận phải giống nhau',
  INVALID: 'Mật khẩu không đúng'
}

export const EmailErrorMessages = {
  INVALID: 'Email không hợp lệ',
  EXISTS: 'Email đã tồn tại trong hệ thống',
  NOT_FOUND: 'Email không tồn tại trong hệ thống'
}

export const OtpErrorMessages = {
  INVALID: 'Mã OTP không hợp lệ',
  EXPIRED: 'Mã OTP đã hết hạn',
  TOO_MANY_ATTEMPTS: 'Quá nhiều lần thử không thành công. Vui lòng yêu cầu mã OTP mới.',
  FAILED_TO_SEND: 'Không thể gửi mã OTP. Vui lòng thử lại sau.'
}

export const TokenErrorMessages = {
  EXPIRED: 'Token đã hết hạn',
  INVALID: 'Token không hợp lệ',
  ALREADY_USED: 'Token đã được sử dụng',
  INVALID_TYPE: 'Loại token không phù hợp cho hoạt động này',
  UNAUTHORIZED: 'Không có quyền truy cập'
}

export const GoogleErrorMessages = {
  FAILED_TO_GET_INFO: 'Không thể lấy thông tin từ Google'
}

// =========== Exception Instances ===========

// OTP related errors
export const InvalidOTPException = new UnprocessableEntityException([
  {
    message: OtpErrorMessages.INVALID,
    path: 'code'
  }
])

export const OTPExpiredException = new UnprocessableEntityException([
  {
    message: OtpErrorMessages.EXPIRED,
    path: 'code'
  }
])

export const TooManyAttemptsException = new UnprocessableEntityException([
  {
    message: OtpErrorMessages.TOO_MANY_ATTEMPTS,
    path: 'code'
  }
])

export const FailedToSendOTPException = new UnprocessableEntityException([
  {
    message: OtpErrorMessages.FAILED_TO_SEND,
    path: 'code'
  }
])

// Email related errors
export const EmailAlreadyExistsException = new UnprocessableEntityException([
  {
    message: EmailErrorMessages.EXISTS,
    path: 'email'
  }
])

export const EmailNotFoundException = new UnprocessableEntityException([
  {
    message: EmailErrorMessages.NOT_FOUND,
    path: 'email'
  }
])

// Password related errors
export const InvalidPasswordException = new UnprocessableEntityException([
  {
    message: PasswordErrorMessages.INVALID,
    path: 'password'
  }
])

// Auth token related errors
export const RefreshTokenAlreadyUsedException = new UnauthorizedException(TokenErrorMessages.ALREADY_USED)
export const UnauthorizedAccessException = new UnauthorizedException(TokenErrorMessages.UNAUTHORIZED)

// Otp token related errors
export const OtpTokenExpiredException = new UnauthorizedException(TokenErrorMessages.EXPIRED)
export const InvalidOtpTokenException = new UnauthorizedException(TokenErrorMessages.INVALID)
export const OtpTokenAlreadyUsedException = new UnauthorizedException(TokenErrorMessages.ALREADY_USED)
export const InvalidOtpTokenTypeException = new UnauthorizedException(TokenErrorMessages.INVALID_TYPE)

// Google auth related errors
export const GoogleUserInfoError = new Error(GoogleErrorMessages.FAILED_TO_GET_INFO)
