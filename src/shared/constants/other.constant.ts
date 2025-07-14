import path from 'path'

export const UPLOAD_DIR = path.resolve('upload')
export const ALL_LANGUAGE_CODE = 'all'
export const OrderBy = {
  Asc: 'asc',
  Desc: 'desc',
} as const

export const SortBy = {
  Price: 'price',
  CreatedAt: 'createdAt',
  Sale: 'sale',
} as const

export const PREFIX_PAYMENT_CODE = 'DH'

export type OrderByType = (typeof OrderBy)[keyof typeof OrderBy]
export type SortByType = (typeof SortBy)[keyof typeof SortBy]
