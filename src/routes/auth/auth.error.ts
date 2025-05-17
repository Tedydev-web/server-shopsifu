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
export const InvalidLoginSessionException = new UnauthorizedException('Error.InvalidLoginSession')

// Cookie related errors
export const MissingAccessTokenException = new UnauthorizedException('Error.MissingAccessToken')
export const InvalidAccessTokenException = new UnauthorizedException('Error.InvalidAccessToken')
export const ExpiredAccessTokenException = new UnauthorizedException('Error.ExpiredAccessToken')
export const MissingRefreshTokenException = new UnauthorizedException('Error.MissingRefreshToken')

// Google auth related errors
export const GoogleUserInfoError = new Error('Error.FailedToGetGoogleUserInfo')

export const InvalidTOTPException = new UnprocessableEntityException([
  {
    message: 'Error.InvalidTOTP',
    path: 'totpCode'
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

export const InvalidRecoveryCodeException = new UnprocessableEntityException([
  {
    message: 'Error.InvalidRecoveryCode',
    path: 'code'
  }
])

// OtpToken related errors
export const InvalidOTPTokenException = new UnprocessableEntityException([
  {
    message: 'Error.InvalidOTPToken',
    path: 'otpToken'
  }
])

export const OTPTokenExpiredException = new UnprocessableEntityException([
  {
    message: 'Error.OTPTokenExpired',
    path: 'otpToken'
  }
])

export const InvalidDeviceException = new UnauthorizedException('Error.InvalidDevice')
export const DeviceMismatchException = new UnprocessableEntityException([
  {
    message: 'Error.DeviceMismatch',
    path: 'device'
  }
])
