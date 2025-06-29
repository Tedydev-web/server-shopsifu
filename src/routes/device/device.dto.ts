import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { DeviceSchema } from './device.model'

// DTO for renaming a device
export const RenameDeviceSchema = z.object({
  name: z.string().min(1, 'Tên không được để trống').max(100, 'Tên không được quá 100 ký tự'),
})
export class RenameDeviceDto extends createZodDto(RenameDeviceSchema) {}

// DTO for serializing the device response
// We create a separate schema for response to avoid serialization issues
// All nullable fields must be properly handled in service layer
export const DeviceResponseSchema = z.object({
  id: z.number().int().positive(),
  name: z.string().min(1),
  ip: z.string().min(1),
  lastActive: z.coerce.date(),
  createdAt: z.coerce.date(),
  browser: z.string().nullable(), // Can be null if browser detection fails
  os: z.string().nullable(), // Can be null if OS detection fails
  deviceType: z.string().nullable(), // Can be null if device type detection fails
})
export class DeviceResponseDto extends createZodDto(DeviceResponseSchema) {}
