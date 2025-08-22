export const OrderShippingStatus = {
  DRAFT: 'DRAFT',
  ENQUEUED: 'ENQUEUED',
  CREATED: 'CREATED',
  FAILED: 'FAILED'
} as const

export type OrderShippingStatusType = (typeof OrderShippingStatus)[keyof typeof OrderShippingStatus]
