import { UnauthorizedException, UnprocessableEntityException } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'

// OTP related errors
export const InvalidOTPException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('auth.auth.error.INVALID_OTP'),
      path: 'code'
    }
  ])

export const OTPExpiredException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('auth.auth.error.OTP_EXPIRED'),
      path: 'code'
    }
  ])

export const FailedToSendOTPException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('auth.auth.error.FAILED_TO_SEND_OTP'),
      path: 'code'
    }
  ])

// Email related errors
export const EmailAlreadyExistsException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('auth.auth.error.EMAIL_ALREADY_EXISTS'),
      path: 'email'
    }
  ])

export const EmailNotFoundException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('auth.auth.error.EMAIL_NOT_FOUND'),
      path: 'email'
    }
  ])

// Auth token related errors
export const RefreshTokenAlreadyUsedException = (i18n: I18nService<I18nTranslations>) =>
  new UnauthorizedException(i18n.t('auth.auth.error.REFRESH_TOKEN_ALREADY_USED'))
export const UnauthorizedAccessException = (i18n: I18nService<I18nTranslations>) =>
  new UnauthorizedException(i18n.t('auth.auth.error.UNAUTHORIZED_ACCESS'))

// Google auth related errors
export const GoogleUserInfoError = (i18n: I18nService<I18nTranslations>) =>
  new Error(i18n.t('auth.auth.error.FAILED_TO_GET_GOOGLE_USER_INFO'))

export const InvalidTOTPException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('auth.auth.error.INVALID_TOTP'),
      path: 'totpCode'
    }
  ])

export const TOTPAlreadyEnabledException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('auth.auth.error.TOTP_ALREADY_ENABLED'),
      path: 'totpCode'
    }
  ])

export const TOTPNotEnabledException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('auth.auth.error.TOTP_NOT_ENABLED'),
      path: 'totpCode'
    }
  ])

export const InvalidTOTPAndCodeException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('auth.auth.error.INVALID_TOTP_AND_CODE'),
      path: 'totpCode'
    },
    {
      message: i18n.t('auth.auth.error.INVALID_TOTP_AND_CODE'),
      path: 'code'
    }
  ])

export const InvalidRefreshTokenException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('auth.auth.error.INVALID_REFRESH_TOKEN'),
      path: 'refreshToken'
    }
  ])

export const RefreshTokenReusedException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('auth.auth.error.REFRESH_TOKEN_REUSED'),
      path: 'refreshToken'
    }
  ])

export const StateTokenMissingException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('auth.auth.error.STATE_TOKEN_MISSING'),
      path: 'stateToken'
    }
  ])
