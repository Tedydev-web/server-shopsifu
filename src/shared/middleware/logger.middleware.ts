import { Injectable, NestMiddleware, Logger } from '@nestjs/common'
import { Request, Response, NextFunction } from 'express'
import { AuditLogService, AuditLogData, AuditLogStatus } from '../services/audit.service' // Giả sử bạn muốn dùng lại AuditLogService
import { REQUEST_USER_KEY } from '../constants/auth.constant'
import { AccessTokenPayload } from '../types/jwt.type'

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  private readonly builtInLogger = new Logger('HTTP') // Logger của NestJS để output ra console nếu cần

  constructor(private readonly auditLogService: AuditLogService) {} // Inject AuditLogService

  use(request: Request, response: Response, next: NextFunction): void {
    const { ip, method, originalUrl, headers: originalHeaders } = request // Đổi tên biến
    const userAgent = originalHeaders['user-agent'] || ''
    const startTime = Date.now()

    response.on('finish', async () => {
      // Thêm async ở đây nếu bạn có thao tác bất đồng bộ lấy userEmail
      const { statusCode } = response
      const contentLength = response.get('content-length')
      const elapsedTime = Date.now() - startTime

      const message = `${method} ${originalUrl} ${statusCode} ${contentLength || '-'} - ${elapsedTime}ms - ${userAgent} ${ip}`

      if (statusCode >= 500) {
        this.builtInLogger.error(message)
      } else if (statusCode >= 400) {
        this.builtInLogger.warn(message)
      } else {
        this.builtInLogger.log(message)
      }

      const activeUser = request[REQUEST_USER_KEY] as AccessTokenPayload | undefined
      let userId: number | undefined
      let userEmail: string | undefined // Sẽ cố gắng lấy email nếu có userId

      if (activeUser) {
        userId = activeUser.userId
        // Tạm thời để userEmail là undefined, bạn có thể bổ sung logic lấy email từ DB nếu cần
        // Ví dụ: if (userId) { const user = await this.prismaService.user.findUnique({ where: {id: userId}, select: {email: true}}); userEmail = user?.email; }
        // Để làm được điều này, bạn cần inject PrismaService vào LoggerMiddleware
      }

      // Lọc headers trước khi ghi vào audit log
      const allowedHeaderKeys = [
        // Danh sách các header được phép log (viết thường)
        'user-agent',
        'referer',
        'content-type',
        'x-forwarded-for',
        'accept-language',
        'x-request-id' // Nếu bạn dùng X-Request-ID/Correlation-ID
      ]
      const sensitiveHeaderKeysPattern = [
        // Danh sách các pattern header nhạy cảm (regex hoặc string)
        /^authorization$/i,
        /^cookie$/i,
        /^x-api-key$/i,
        /^x-csrf-token$/i,
        /secret/i,
        /token/i, // Rộng, nhưng có thể bắt được các custom token headers
        /password/i
      ]

      const filteredHeaders: Record<string, string | string[] | undefined> = {}
      for (const key in originalHeaders) {
        const lowerKey = key.toLowerCase()
        let isSensitive = false
        for (const pattern of sensitiveHeaderKeysPattern) {
          if (typeof pattern === 'string' && lowerKey === pattern) {
            isSensitive = true
            break
          }
          if (pattern instanceof RegExp && pattern.test(lowerKey)) {
            isSensitive = true
            break
          }
        }

        if (isSensitive) {
          // Ghi nhận là header đã bị che dấu thay vì loại bỏ hoàn toàn để biết nó tồn tại
          filteredHeaders[key] = '[REDACTED_SENSITIVE_HEADER]'
        } else if (allowedHeaderKeys.includes(lowerKey)) {
          filteredHeaders[key] = originalHeaders[key]
        } else {
          // Đối với các header không nằm trong danh sách cho phép và không nhạy cảm,
          // bạn có thể chọn log giá trị bị che một phần hoặc bỏ qua.
          // Hiện tại đang bỏ qua để giữ log gọn.
          // filteredHeaders[key] = '[REDACTED_OTHER_HEADER]';
        }
      }

      const auditLogEntry: AuditLogData = {
        action: 'HTTP_REQUEST',
        userId: userId,
        userEmail: userEmail,
        entity: originalUrl,
        details: {
          method,
          statusCode,
          contentLength: contentLength || undefined,
          elapsedTimeMs: elapsedTime,
          requestHeaders: filteredHeaders // Sử dụng headers đã lọc
        },
        ipAddress: ip,
        userAgent: userAgent,
        status: statusCode >= 400 ? AuditLogStatus.FAILURE : AuditLogStatus.SUCCESS,
        errorMessage: statusCode >= 400 ? `HTTP Error: ${statusCode}` : undefined,
        notes: `Access log for ${method} ${originalUrl}`
      }
      try {
        await this.auditLogService.record(auditLogEntry)
      } catch (error) {
        this.builtInLogger.error('Failed to record HTTP access audit log:', error)
      }
    })

    next()
  }
}
