import { UnprocessableEntityException, NotFoundException } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'

export const BrandTranslationAlreadyExistsException = (i18n: I18nService<I18nTranslations>) =>
  new UnprocessableEntityException([
    {
      path: 'languageId',
      message: i18n.t('brand.brandTranslation.error.ALREADY_EXISTS')
    }
  ])

export const BrandTranslationBrandNotFoundException = (i18n: I18nService<I18nTranslations>) =>
  new NotFoundException([
    {
      path: 'brandId',
      message: i18n.t('brand.brandTranslation.error.BRAND_NOT_FOUND')
    }
  ])

export const BrandTranslationLanguageNotFoundException = (i18n: I18nService<I18nTranslations>) =>
  new NotFoundException([
    {
      path: 'languageId',
      message: i18n.t('brand.brandTranslation.error.LANGUAGE_NOT_FOUND')
    }
  ])
