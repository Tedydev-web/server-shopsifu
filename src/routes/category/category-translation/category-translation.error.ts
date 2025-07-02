import { UnprocessableEntityException } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'

export const CategoryTranslationAlreadyExistsException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      path: 'languageId',
      message: i18n.t('category.error.ALREADY_EXISTS'),
    },
  ])
