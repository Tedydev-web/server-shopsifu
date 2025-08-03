/**
 * Search sort fields
 */
export const SEARCH_SORT_FIELDS = {
  PRICE: 'skuPrice',
  CREATED_AT: 'createdAt',
  UPDATED_AT: 'updatedAt',
  SCORE: '_score'
} as const

/**
 * Search sort orders
 */
export const SEARCH_SORT_ORDERS = {
  ASC: 'asc',
  DESC: 'desc'
} as const

/**
 * Default pagination cho search
 */
export const DEFAULT_PAGINATION = {
  PAGE: 1,
  LIMIT: 20,
  MAX_LIMIT: 100
} as const

/**
 * Search timeout (milliseconds)
 */
export const SEARCH_TIMEOUT = 30000

/**
 * Search index name
 */
export const SEARCH_INDEX_PRODUCTS = 'products_v1'
