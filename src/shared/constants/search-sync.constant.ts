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
 * Job options cho BullMQ
 */
export const JOB_OPTIONS = {
  ATTEMPTS: 3,
  BACKOFF: {
    type: 'exponential',
    delay: 2000
  },
  REMOVE_ON_COMPLETE: 100,
  REMOVE_ON_FAIL: 100
} as const
