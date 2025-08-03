/**
 * Queue names cho search sync
 */
export const SEARCH_SYNC_QUEUE_NAME = 'search-sync'

/**
 * Job names cho search sync
 */
export const SYNC_PRODUCT_JOB = 'sync-product'
export const SYNC_PRODUCTS_BATCH_JOB = 'sync-products-batch'
export const DELETE_PRODUCT_JOB = 'delete-product'

/**
 * Index names cho Elasticsearch
 */
export const ES_INDEX_PRODUCTS = 'products'

/**
 * Sync actions
 */
export const SYNC_ACTIONS = {
  CREATE: 'create',
  UPDATE: 'update',
  DELETE: 'delete'
} as const

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
 * Default pagination
 */
export const DEFAULT_PAGINATION = {
  PAGE: 1,
  LIMIT: 20,
  MAX_LIMIT: 100
} as const

/**
 * Job options
 */
export const JOB_OPTIONS = {
  // Retry options
  ATTEMPTS: 3,
  BACKOFF: {
    type: 'exponential',
    delay: 2000
  },
  // Remove completed jobs after 24 hours
  REMOVE_ON_COMPLETE: 100,
  REMOVE_ON_FAIL: 100
} as const
