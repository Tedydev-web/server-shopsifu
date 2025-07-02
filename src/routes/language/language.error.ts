import { ConflictException } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/generated/i18n.generated'

export const LanguageAlreadyExistsException = (i18n: I18nService<I18nTranslations>) =>
  new ConflictException([
    {
      message: 'language.error.ALREADY_EXISTS',
      path: 'id',
    },
  ])
