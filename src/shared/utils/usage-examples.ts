/**
 * File này chứa các ví dụ về cách sử dụng các tiện ích và dịch vụ mới
 * CHÚ Ý: Đây chỉ là file ví dụ, không sử dụng trong sản phẩm thực tế.
 */
import { Controller, Get, Post, Body, Req, HttpStatus } from '@nestjs/common'
import { Request } from 'express'
import { AuditLogService, AuditLogStatus } from '../services/audit.service'
import { AuditLog } from '../decorators/audit-log.decorator'
import { DeviceService } from '../services/device.service'
import { createAuditLog, maskSensitiveFields } from '../utils/audit-log.utils'
import { validateWithZod, safeString, safeNumber, pick, omit } from '../utils/validation.utils'
import { z } from 'zod'
import { ApiException } from '../exceptions/api.exception'

// Ví dụ schema Zod cho validation
const UserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  name: z.string().min(2),
  age: z.number().min(18).optional()
})

type User = z.infer<typeof UserSchema>

// Ví dụ 1: Sử dụng AuditLog decorator
@Controller('examples')
export class ExampleController {
  constructor(
    private readonly auditLogService: AuditLogService,
    private readonly deviceService: DeviceService
  ) {}

  // Ví dụ sử dụng AuditLog decorator
  @Post('users')
  @AuditLog({
    action: 'USER_CREATE',
    entity: 'User',
    getUserId: (params) => params[0]?.userId,
    getEntityId: (_, result) => result?.id,
    getDetails: (params) => ({
      email: params[0]?.email,
      userType: params[0]?.userType
    })
  })
  async createUser(@Body() userData: any) {
    // Xác thực dữ liệu với Zod
    try {
      const validatedData = validateWithZod(UserSchema, userData, 'Dữ liệu người dùng không hợp lệ')
      // Tiếp tục xử lý với dữ liệu đã được xác thực
      return { id: 123, ...validatedData }
    } catch (error) {
      // AuditLog decorator sẽ tự động ghi log lỗi
      throw error
    }
  }

  // Ví dụ sử dụng createAuditLog utility
  @Get('products')
  async getProducts(@Req() request: Request) {
    try {
      // Logic lấy danh sách sản phẩm
      const products = [
        { id: 1, name: 'Product 1' },
        { id: 2, name: 'Product 2' }
      ]

      // Ghi log với createAuditLog utility
      this.auditLogService.recordAsync(
        createAuditLog(
          {
            request,
            result: products
          },
          {
            action: 'PRODUCT_LIST_VIEW',
            entity: 'Product',
            includeRequest: true,
            includeRequestBody: false
          }
        )
      )

      return products
    } catch (error) {
      // Ghi log lỗi
      this.auditLogService.recordAsync(
        createAuditLog(
          {
            request,
            error
          },
          {
            action: 'PRODUCT_LIST_VIEW',
            status: AuditLogStatus.FAILURE,
            includeRequest: true
          }
        )
      )
      throw error
    }
  }

  // Ví dụ sử dụng các utility functions
  @Post('validate-data')
  async validateData(@Body() data: any) {
    try {
      // Sử dụng utility functions để làm sạch và chuyển đổi dữ liệu
      const cleanData = {
        name: safeString(data.name),
        age: safeNumber(data.age, 0),
        isActive: data.isActive === true,
        // Loại bỏ thông tin nhạy cảm
        sensitiveData: maskSensitiveFields(data.sensitive)
      }

      // Sử dụng pick và omit
      const publicUserData = pick(cleanData, ['name', 'age', 'isActive'])
      const withoutAgeData = omit(cleanData, ['age'])

      return {
        valid: true,
        cleanData,
        publicUserData,
        withoutAgeData
      }
    } catch (error) {
      throw new ApiException(HttpStatus.BAD_REQUEST, 'VALIDATION_ERROR', 'Error.Validation.Failed', [
        { code: 'Error.Validation.InvalidData' }
      ])
    }
  }
}

// Ví dụ 2: Sử dụng DeviceService với AuditLog
export class AuthExample {
  constructor(
    private readonly deviceService: DeviceService,
    private readonly auditLogService: AuditLogService
  ) {}

  // Ví dụ tích hợp DeviceService với AuditLog
  async login(email: string, password: string, userAgent: string, ip: string) {
    try {
      // 1. Giả định: Xác thực thành công
      const userId = 123

      // 2. Tạo hoặc cập nhật thông tin thiết bị
      const device = await this.deviceService.findOrCreateDevice({
        userId,
        userAgent,
        ip
      })

      // 3. Ghi log thành công với AuditLogService tiện ích mới
      this.auditLogService.success('USER_LOGIN', {
        userId,
        userEmail: email,
        entityId: userId,
        entity: 'User',
        ipAddress: ip,
        userAgent: userAgent,
        details: {
          deviceId: device.id,
          loginMethod: 'password'
        }
      })

      return { success: true, userId, deviceId: device.id }
    } catch (error) {
      // Ghi log thất bại
      this.auditLogService.failure('USER_LOGIN', {
        userEmail: email,
        ipAddress: ip,
        userAgent: userAgent,
        errorMessage: error.message,
        details: {
          reason: 'authentication_failed',
          errorDetails: error.stack
        }
      })

      throw error
    }
  }
}
