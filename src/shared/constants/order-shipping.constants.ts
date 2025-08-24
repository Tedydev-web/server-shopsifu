export const OrderShippingStatus = {
  DRAFT: 'DRAFT',
  ENQUEUED: 'ENQUEUED',
  CREATED: 'CREATED',
  FAILED: 'FAILED',
  CANCELLED: 'CANCELLED'
} as const

export type OrderShippingStatusType = (typeof OrderShippingStatus)[keyof typeof OrderShippingStatus]
