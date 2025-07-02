import { UnprocessableEntityException } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'

export const PermissionAlreadyExistsException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      message: i18n.t('permission.error.ALREADY_EXISTS'),
      path: 'path',
    },
    {
      message: i18n.t('permission.error.ALREADY_EXISTS'),
      path: 'method',
    },
  ])
