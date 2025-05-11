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

// Auth token related errors
export const RefreshTokenAlreadyUsedException = new UnauthorizedException('Error.RefreshTokenAlreadyUsed')
export const UnauthorizedAccessException = new UnauthorizedException('Error.UnauthorizedAccess')

// Otp token related errors
export const OtpTokenExpiredException = new UnauthorizedException('Error.OtpTokenExpired')
export const InvalidOtpTokenException = new UnauthorizedException('Error.InvalidOtpToken')
export const OtpTokenAlreadyUsedException = new UnauthorizedException('Error.OtpTokenAlreadyUsed')
export const InvalidOtpTokenTypeException = new UnauthorizedException('Error.InvalidOtpTokenType')

// Google auth related errors
export const GoogleUserInfoError = new Error('Error.FailedToGetGoogleUserInfo')
