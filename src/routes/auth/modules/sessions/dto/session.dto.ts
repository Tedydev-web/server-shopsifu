import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

// Session Item DTO (chỉ các trường cần thiết cho UI)
export const SessionItemSchema = z.object({
  id: z.string(),
  createdAt: z.date(),
  lastActive: z.date(),
  ipAddress: z.string(),
  userAgent: z.string(),
  isCurrentSession: z.boolean() // Thêm trường này để UI biết session hiện tại
})

// Device Group DTO
export const DeviceSessionGroupSchema = z.object({
  deviceId: z.number(),
  deviceName: z.string().nullable(),
  isDeviceTrusted: z.boolean(),
  deviceTrustExpiration: z.date().nullable().optional(), // Thêm thời gian hết hạn tin cậy
  sessions: z.array(SessionItemSchema)
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

// Schema cho body khi revoke nhiều items (có thể là session hoặc device)
export const RevokeItemsBodySchema = z.object({
  sessionIds: z.array(z.string()).optional(),
  deviceIds: z.array(z.number()).optional(),
  revokeAllUserSessions: z.boolean().optional().default(false),
  excludeCurrentSession: z.boolean().optional().default(false) // Áp dụng nếu revokeAllUserSessions là true
})

export const RevokeItemsResponseSchema = z.object({
  message: z.string(),
  revokedSessionsCount: z.number(),
  revokedDevicesCount: z.number(),
  untrustedDevicesCount: z.number()
})

// Update Device DTOs
export const DeviceIdParamsSchema = z.object({
  deviceId: z.coerce.number() // Chuyển sang number cho nhất quán
})

export const UpdateDeviceNameBodySchema = z.object({
  name: z.string().min(1).max(100)
})

// Trust/Untrust Device DTOs (Không cần body nữa nếu chỉ dựa vào params)

// DTO classes
export class GetSessionsQueryDto extends createZodDto(GetSessionsQuerySchema) {}
export class SessionItemDto extends createZodDto(SessionItemSchema) {}
export class DeviceSessionGroupDto extends createZodDto(DeviceSessionGroupSchema) {}
export class GetGroupedSessionsResponseDto extends createZodDto(GetGroupedSessionsResponseSchema) {}

export class RevokeSessionParamsDto extends createZodDto(RevokeSessionParamsSchema) {}
export class RevokeItemsBodyDto extends createZodDto(RevokeItemsBodySchema) {}
export class RevokeItemsResponseDto extends createZodDto(RevokeItemsResponseSchema) {}

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
