import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

// Session Item DTO (chi tiết theo yêu cầu)
export const SessionItemSchema = z.object({
  id: z.string(),
  createdAt: z.date(),
  lastActive: z.date(),
  ipAddress: z.string(),
  location: z.string().nullable().optional(),
  browser: z.string().nullable().optional(),
  browserVersion: z.string().nullable().optional(),
  app: z.string().nullable().optional(),
  isActive: z.boolean().default(true),
  inactiveDuration: z.string().nullable().optional(),
  isCurrentSession: z.boolean().default(false) // Đánh dấu session hiện tại
})

// Device Group DTO với thông tin chi tiết hơn
export const DeviceSessionGroupSchema = z.object({
  deviceId: z.number(),
  deviceName: z.string().nullable(),
  deviceType: z.string().nullable().optional(),
  os: z.string().nullable().optional(),
  osVersion: z.string().nullable().optional(),
  browser: z.string().nullable().optional(),
  browserVersion: z.string().nullable().optional(),
  isDeviceTrusted: z.boolean(),
  deviceTrustExpiration: z.date().nullable().optional(),
  lastActive: z.date().nullable().optional(),
  location: z.string().nullable().optional(),
  activeSessionsCount: z.number().optional(),
  sessions: z.array(SessionItemSchema),
  isCurrentDevice: z.boolean().default(false) // Thêm trường đánh dấu thiết bị hiện tại
})

// Get Sessions DTOs
export const GetSessionsQuerySchema = z.object({
  page: z.coerce.number().min(1).default(1), // Phân trang theo devices
  limit: z.coerce.number().min(1).max(100).default(5) // Số lượng devices mỗi trang
})

export const GetGroupedSessionsResponseSchema = z.object({
  devices: z.array(DeviceSessionGroupSchema),
  meta: z.object({
    currentPage: z.number(),
    itemsPerPage: z.number(),
    totalItems: z.number(), // Tổng số devices
    totalPages: z.number()
  })
})

// Revoke Session DTOs
export const RevokeSessionParamsSchema = z.object({
  sessionId: z.string()
})

// Thay thế RevokeItemsBodySchema cũ
export const RevokeSessionsBodySchema = z
  .object({
    // Các sessions cần thu hồi (option 1)
    sessionIds: z.array(z.string()).optional(),

    // Các devices cần thu hồi (option 2)
    deviceIds: z.array(z.number()).optional(),

    // Loại trừ session hiện tại (thường là true để không tự logout)
    excludeCurrentSession: z.boolean().default(true),

    // Xác thực bổ sung khi cần
    verificationToken: z.string().optional(),
    otpCode: z.string().optional()
  })
  .refine(({ sessionIds, deviceIds }) => !!sessionIds?.length || !!deviceIds?.length, {
    message: 'Bạn phải chỉ định ít nhất một trong các tùy chọn: sessionIds hoặc deviceIds',
    path: ['invalidRevocationParameters']
  })

// Thêm schema mới cho revoke-all
export const RevokeAllSessionsBodySchema = z.object({
  // Loại trừ session hiện tại (mặc định là true)
  excludeCurrentSession: z.boolean().default(true),

  // Xác thực bổ sung khi cần
  verificationToken: z.string().optional(),
  otpCode: z.string().optional()
})

// Thay thế RevokeItemsResponseSchema cũ
export const RevokeSessionsResponseSchema = z.object({
  // Số lượng sessions đã được thu hồi
  revokedSessionsCount: z.number(),

  // Số lượng devices đã bị untrust
  untrustedDevicesCount: z.number(),

  // Chi tiết các sessions đã thu hồi (tùy chọn)
  revokedSessionIds: z.array(z.string()).optional(),

  // Chi tiết các devices đã thu hồi (tùy chọn)
  revokedDeviceIds: z.array(z.number()).optional(),

  // Nếu cần xác thực bổ sung
  requiresAdditionalVerification: z.boolean().default(false),

  // Loại xác thực: '2FA' hoặc 'OTP'
  verificationType: z.enum(['2FA', 'OTP']).optional(),

  // URL để chuyển hướng nếu cần xác thực bổ sung
  verificationRedirectUrl: z.string().optional()
})

// Thay thế DTO cũ
export class RevokeSessionsBodyDto extends createZodDto(RevokeSessionsBodySchema) {}
export class RevokeSessionsResponseDto extends createZodDto(RevokeSessionsResponseSchema) {}
export class RevokeAllSessionsBodyDto extends createZodDto(RevokeAllSessionsBodySchema) {}

// Update Device DTOs
export const DeviceIdParamsSchema = z.object({
  deviceId: z.coerce.number() // Chuyển sang number cho nhất quán
})

export const UpdateDeviceNameBodySchema = z.object({
  name: z.string().min(1).max(100)
})

// Trust/Untrust Device DTOs (Không cần body nếu chỉ dựa vào params)

// DTO classes
export class GetSessionsQueryDto extends createZodDto(GetSessionsQuerySchema) {}
export class SessionItemDto extends createZodDto(SessionItemSchema) {}
export class DeviceSessionGroupDto extends createZodDto(DeviceSessionGroupSchema) {}
export class GetGroupedSessionsResponseDto extends createZodDto(GetGroupedSessionsResponseSchema) {}

export class RevokeSessionParamsDto extends createZodDto(RevokeSessionParamsSchema) {}
export class DeviceIdParamsDto extends createZodDto(DeviceIdParamsSchema) {}
export class UpdateDeviceNameBodyDto extends createZodDto(UpdateDeviceNameBodySchema) {}

// Các DTO không thay đổi nhiều có thể giữ lại hoặc gộp nếu cần
export const RevokeSessionResponseSchema = z.object({
  message: z.string()
})
export class RevokeSessionResponseDto extends createZodDto(RevokeSessionResponseSchema) {}

export const UpdateDeviceNameResponseSchema = z.object({
  message: z.string()
})
export class UpdateDeviceNameResponseDto extends createZodDto(UpdateDeviceNameResponseSchema) {}

export const TrustDeviceResponseSchema = z.object({
  message: z.string()
})
export class TrustDeviceResponseDto extends createZodDto(TrustDeviceResponseSchema) {}

export const UntrustDeviceResponseSchema = z.object({
  message: z.string()
})
export class UntrustDeviceResponseDto extends createZodDto(UntrustDeviceResponseSchema) {}
