import { UnauthorizedException, UnprocessableEntityException } from '@nestjs/common'

// OTP related errors
export const InvalidOTPException = new UnprocessableEntityException([
  {
    message: 'ERROR.INVALID_OTP',
    path: 'code'
  }
])

export const OTPExpiredException = new UnprocessableEntityException([
  {
    message: 'ERROR.OTP_EXPIRED',
    path: 'code'
  }
])

export const FailedToSendOTPException = new UnprocessableEntityException([
  {
    message: 'ERROR.FAILED_TO_SEND_OTP',
    path: 'code'
  }
])

// Email related errors
export const EmailAlreadyExistsException = new UnprocessableEntityException([
  {
    message: 'ERROR.EMAIL_ALREADY_EXISTS',
    path: 'email'
  }
])

export const EmailNotFoundException = new UnprocessableEntityException([
  {
    message: 'ERROR.EMAIL_NOT_FOUND',
    path: 'email'
  }
])

// Password related errors
export const InvalidPasswordException = new UnprocessableEntityException([
  {
    message: 'ERROR.INVALID_PASSWORD',
    path: 'password'
  }
])

// Thêm error mới cho OTP token
export const InvalidOTPTokenException = new UnauthorizedException([
  {
    message: 'ERROR.INVALID_OTP_TOKEN',
    path: 'otpToken'
  }
])

export const OTPTokenExpiredException = new UnauthorizedException([
  {
    message: 'ERROR.OTP_TOKEN_EXPIRED',
    path: 'otpToken'
  }
])

// Auth token related errors
export const RefreshTokenAlreadyUsedException = new UnauthorizedException({
  message: 'ERROR.REFRESH_TOKEN_ALREADY_USED'
})

export const UnauthorizedAccessException = new UnauthorizedException({
  message: 'ERROR.UNAUTHORIZED_ACCESS'
})

// Google auth related errors
export const GoogleUserInfoError = new Error('ERROR.FAILED_TO_GET_GOOGLE_USER_INFO')
export const PasswordConfirmationMismatchException = new UnprocessableEntityException([
  {
    message: 'ERROR.PASSWORD_CONFIRMATION_MISMATCH',
    path: 'confirmPassword'
  }
])

export const TOTPAlreadyEnabledException = new UnprocessableEntityException([
  {
    message: 'Error.TOTPAlreadyEnabled',
    path: 'totpCode'
  }
])

export const TOTPNotEnabledException = new UnprocessableEntityException([
  {
    message: 'Error.TOTPNotEnabled',
    path: 'totpCode'
  }
])

export const InvalidTOTPAndCodeException = new UnprocessableEntityException([
  {
    message: 'Error.InvalidTOTPAndCode',
    path: 'totpCode'
  },
  {
    message: 'Error.InvalidTOTPAndCode',
    path: 'code'
  }
])
