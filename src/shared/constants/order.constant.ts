export const OrderStatus = {
  // 🚫 Trạng thái ban đầu (sau khi tạo order)
  PENDING_PAYMENT: 'PENDING_PAYMENT', // Chờ thanh toán (COD) hoặc xác nhận (Online)

  // 📦 Trạng thái xử lý (Seller quản lý)
  PENDING_PACKAGING: 'PENDING_PACKAGING', // Người bán đang chuẩn bị hàng

  // 🚚 Trạng thái vận chuyển (Shipping)
  PICKUPED: 'PICKUPED', // ĐVVC đã lấy hàng thành công
  PENDING_DELIVERY: 'PENDING_DELIVERY', // Đơn hàng đang trong quá trình vận chuyển

  // ✅ Trạng thái hoàn thành
  DELIVERED: 'DELIVERED', // Đã giao hàng thành công

  // ❌ Trạng thái hủy/hoàn
  CANCELLED: 'CANCELLED', // Đơn hàng bị hủy
  RETURNED: 'RETURNED' // Đơn hàng bị hoàn trả
} as const

export type OrderStatusType = (typeof OrderStatus)[keyof typeof OrderStatus]

// 🎯 Flow chuẩn hóa cho cả COD và Online
export const ORDER_STATUS_FLOW = {
  // COD Flow: PENDING_PAYMENT → PENDING_PACKAGING → PICKUPED → PENDING_DELIVERY → DELIVERED
  // Online Flow: PENDING_PACKAGING → PICKUPED → PENDING_DELIVERY → DELIVERED

  // Trạng thái chỉ Admin có thể cập nhật
  ADMIN_ONLY: [
    OrderStatus.PENDING_PAYMENT,
    OrderStatus.PENDING_PACKAGING,
    OrderStatus.PICKUPED,
    OrderStatus.PENDING_DELIVERY,
    OrderStatus.DELIVERED,
    OrderStatus.CANCELLED,
    OrderStatus.RETURNED
  ],

  // Flow chuyển đổi hợp lệ
  VALID_TRANSITIONS: {
    [OrderStatus.PENDING_PAYMENT]: [OrderStatus.PENDING_PACKAGING, OrderStatus.CANCELLED],
    [OrderStatus.PENDING_PACKAGING]: [OrderStatus.PICKUPED, OrderStatus.CANCELLED],
    [OrderStatus.PICKUPED]: [OrderStatus.PENDING_DELIVERY, OrderStatus.CANCELLED],
    [OrderStatus.PENDING_DELIVERY]: [OrderStatus.DELIVERED, OrderStatus.CANCELLED],
    [OrderStatus.DELIVERED]: [OrderStatus.RETURNED],
    [OrderStatus.CANCELLED]: [], // Không thể chuyển từ CANCELLED
    [OrderStatus.RETURNED]: [] // Không thể chuyển từ RETURNED
  }
} as const
