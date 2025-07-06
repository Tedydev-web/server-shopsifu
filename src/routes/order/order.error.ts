import { BadRequestException, NotFoundException } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'

export const OrderNotFoundException = (i18n: I18nService<I18nTranslations>) =>
  new NotFoundException(i18n.t('order.order.error.NOT_FOUND'))
export const ProductNotFoundException = (i18n: I18nService<I18nTranslations>) =>
  new NotFoundException(i18n.t('order.order.error.PRODUCT_NOT_FOUND'))
export const OutOfStockSKUException = (i18n: I18nService<I18nTranslations>) =>
  new BadRequestException(i18n.t('order.order.error.OUT_OF_STOCK_SKU'))
export const NotFoundCartItemException = (i18n: I18nService<I18nTranslations>) =>
  new NotFoundException(i18n.t('order.order.error.NOT_FOUND_CART_ITEM'))
export const SKUNotBelongToShopException = (i18n: I18nService<I18nTranslations>) =>
  new BadRequestException(i18n.t('order.order.error.SKU_NOT_BELONG_TO_SHOP'))
export const CannotCancelOrderException = (i18n: I18nService<I18nTranslations>) =>
  new BadRequestException(i18n.t('order.order.error.CANNOT_CANCEL'))
