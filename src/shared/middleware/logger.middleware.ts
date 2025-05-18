import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { AuditLogService, AuditLogData, AuditLogStatus } from '../services/audit.service'; // Giả sử bạn muốn dùng lại AuditLogService
import { REQUEST_USER_KEY } from '../constants/auth.constant';
import { AccessTokenPayload } from '../types/jwt.type';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  private readonly builtInLogger = new Logger('HTTP'); // Logger của NestJS để output ra console nếu cần
  
  constructor(private readonly auditLogService: AuditLogService) {} // Inject AuditLogService

  use(request: Request, response: Response, next: NextFunction): void {
    const { ip, method, originalUrl, headers } = request;
    const userAgent = headers['user-agent'] || '';
    const startTime = Date.now();

    response.on('finish', () => {
      const { statusCode } = response;
      const contentLength = response.get('content-length');
      const elapsedTime = Date.now() - startTime;

      const message = `${method} ${originalUrl} ${statusCode} ${contentLength || '-'} - ${elapsedTime}ms - ${userAgent} ${ip}`;
      
      if (statusCode >= 500) {
        this.builtInLogger.error(message);
      } else if (statusCode >= 400) {
        this.builtInLogger.warn(message);
      } else {
        this.builtInLogger.log(message);
      }

      // Ghi Access Log vào DB thông qua AuditLogService
      // Bạn có thể tùy chỉnh action và details tùy theo nhu cầu
      const activeUser = request[REQUEST_USER_KEY] as AccessTokenPayload | undefined;
      let userId: number | undefined;
      let userEmail: string | undefined;

      if (activeUser) {
        userId = activeUser.userId;
        // Bạn có thể lấy email từ DB nếu cần và nếu có payload user trong request
        // Hoặc nếu AccessTokenPayload của bạn chứa email thì lấy trực tiếp
      }

      const auditLogEntry: AuditLogData = {
        action: 'HTTP_REQUEST',
        userId: userId,
        userEmail: userEmail, // Cần lấy email nếu muốn log
        entity: originalUrl,
        details: {
          method,
          statusCode,
          contentLength,
          elapsedTimeMs: elapsedTime,
          requestHeaders: headers, // Cẩn thận với việc log toàn bộ headers vì có thể chứa thông tin nhạy cảm
        },
        ipAddress: ip,
        userAgent: userAgent,
        status: statusCode >= 400 ? AuditLogStatus.FAILURE : AuditLogStatus.SUCCESS,
        errorMessage: statusCode >= 400 ? `HTTP Error: ${statusCode}` : undefined,
        notes: `Access log for ${method} ${originalUrl}`
      };
      this.auditLogService.record(auditLogEntry);
    });

    next();
  }
} 