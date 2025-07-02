import { ForbiddenException, UnprocessableEntityException } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'

export const RoleAlreadyExistsException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
  {
    message: i18n.t('role.error.ALREADY_EXISTS'),
    path: 'name',
  },
])

export const ProhibitedActionOnBaseRoleException = new ForbiddenException('Error.ProhibitedActionOnBaseRole')
