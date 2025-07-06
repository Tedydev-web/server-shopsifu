import { BadRequestException, NotFoundException } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'

export const NotFoundSKUException = (i18n: I18nService<I18nTranslations>) =>
  new NotFoundException(i18n.t('cart.cart.error.SKU_NOT_FOUND'))

export const OutOfStockSKUException = (i18n: I18nService<I18nTranslations>) =>
  new BadRequestException(i18n.t('cart.cart.error.SKU_OUT_OF_STOCK'))

export const ProductNotFoundException = (i18n: I18nService<I18nTranslations>) =>
  new NotFoundException(i18n.t('cart.cart.error.PRODUCT_NOT_FOUND'))

export const NotFoundCartItemException = (i18n: I18nService<I18nTranslations>) =>
  new NotFoundException(i18n.t('cart.cart.error.CART_ITEM_NOT_FOUND'))

export const InvalidQuantityException = (i18n: I18nService<I18nTranslations>) =>
  new BadRequestException(i18n.t('cart.cart.error.INVALID_QUANTITY'))
