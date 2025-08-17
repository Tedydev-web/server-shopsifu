export const DiscountType = {
  FIX_AMOUNT: 'FIX_AMOUNT',
  PERCENTAGE: 'PERCENTAGE'
} as const

export const DiscountStatus = {
  DRAFT: 'DRAFT',
  INACTIVE: 'INACTIVE',
  ACTIVE: 'ACTIVE',
  EXPIRED: 'EXPIRED'
} as const

export const DiscountApplyType = {
  ALL: 'ALL',
  SPECIFIC: 'SPECIFIC'
} as const

export const VoucherType = {
  SHOP: 'SHOP',
  PRODUCT: 'PRODUCT',
  PLATFORM: 'PLATFORM',
  CATEGORY: 'CATEGORY',
  BRAND: 'BRAND'
} as const

export const DisplayType = {
  PUBLIC: 'PUBLIC',
  PRIVATE: 'PRIVATE'
} as const
