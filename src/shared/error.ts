import { NotFoundException, UnprocessableEntityException } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'

export const NotFoundRecordException = (i18n: I18nService<I18nTranslations>) =>
  new NotFoundException([{ message: i18n.t('global.global.error.NOT_FOUND_RECORD') }])

export const InvalidPasswordException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('global.global.error.INVALID_PASSWORD'),
      path: 'password'
    }
  ])

export const UnauthorizedException = (i18n: I18nService<I18nTranslations>) => [
  {
    message: i18n.t('global.global.error.UNAUTHORIZED'),
    path: 'token'
  }
]

export const ForbiddenException = (i18n: I18nService<I18nTranslations>) => [
  {
    message: i18n.t('global.global.error.FORBIDDEN'),
    path: 'token'
  }
]

export const UserNotActiveException = (i18n: I18nService<I18nTranslations>) => [
  {
    message: i18n.t('global.global.error.USER_NOT_ACTIVE'),
    path: 'user'
  }
]

export const InsufficientPermissionsException = (i18n: I18nService<I18nTranslations>) => [
  {
    message: i18n.t('global.global.error.INSUFFICIENT_PERMISSIONS'),
    path: 'user'
  }
]

export const SessionNotFoundException = (i18n: I18nService<I18nTranslations>) => [
  {
    message: i18n.t('global.global.error.SESSION_NOT_FOUND'),
    path: 'session'
  }
]

export const TokenBlacklistedException = (i18n: I18nService<I18nTranslations>) => [
  {
    message: i18n.t('global.global.error.TOKEN_BLACKLISTED'),
    path: 'token'
  }
]