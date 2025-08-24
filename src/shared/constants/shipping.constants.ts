export const GHN_CLIENT = 'GHN_CLIENT' as const

// GHN Payment Types
export const GHN_PAYMENT_TYPE = {
  PREPAID: 1, // Thanh toán trước
  COD: 2 // Thanh toán khi nhận hàng
} as const

// GHN Order status Mapping
export const GHN_ORDER_STATUS = {
  CREATED: 'CREATED',
  PICKUPED: 'PICKUPED',
  PICKED_UP: 'PICKED_UP',
  IN_TRANSIT: 'IN_TRANSIT',
  DELIVERED: 'DELIVERED',
  CANCELLED: 'CANCELLED',
  RETURNED: 'RETURNED'
} as const

// GHN Service Types
export const GHN_SERVICE_TYPE = {
  STANDARD: 1, // Dịch vụ tiêu chuẩn
  EXPRESS: 2, // Dịch vụ nhanh
  ECONOMY: 3 // Dịch vụ tiết kiệm
} as const
