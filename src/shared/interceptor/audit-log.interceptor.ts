import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Inject,
  Optional,
  Scope,
  Logger
} from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Observable } from 'rxjs'
import { tap, catchError, finalize } from 'rxjs/operators'
import { AuditLogService, AuditLogStatus, AuditLogData } from '../services/audit.service'
import { AUDIT_LOG_KEY, AuditLogOptions } from '../decorators/audit-log.decorator'
import { REQUEST } from '@nestjs/core'
import { Request, Response } from 'express'
import { REQUEST_USER_KEY } from '../constants/auth.constant'
import { AccessTokenPayload } from '../types/jwt.type'
import { isNullOrUndefined, isObject, normalizeErrorMessage, isApiException } from '../utils/type-guards'

@Injectable({ scope: Scope.REQUEST })
export class AuditLogInterceptor implements NestInterceptor {
  private readonly logger = new Logger(AuditLogInterceptor.name)

  constructor(
    private readonly reflector: Reflector,
    private readonly auditLogService: AuditLogService,
    @Optional() @Inject(REQUEST) private readonly request?: Request
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const auditLogOptions = this.reflector.get<AuditLogOptions>(AUDIT_LOG_KEY, context.getHandler())

    if (!auditLogOptions) {
      return next.handle()
    }

    const args = this.getArgs(context)
    const req = this.getRequest(context)
    const res = this.getResponse(context)
    const userFromRequest = req?.[REQUEST_USER_KEY] as AccessTokenPayload | undefined
    const startTime = Date.now()

    return next.handle().pipe(
      tap((result) => {
        // Xử lý thành công
        const auditLogData = this.buildAuditLogData(auditLogOptions, args, result, userFromRequest, req, res, true)
        void this.auditLogService.record(auditLogData)
      }),
      catchError((error) => {
        // Xử lý lỗi
        const auditLogData = this.buildAuditLogData(
          auditLogOptions,
          args,
          undefined,
          userFromRequest,
          req,
          res,
          false,
          error
        )
        void this.auditLogService.record(auditLogData)
        throw error // Re-throw để middleware exception filter xử lý
      }),
      finalize(() => {
        const executionTime = Date.now() - startTime
        this.logger.debug(`Method execution completed in ${executionTime}ms`)
      })
    )
  }

  private getArgs(context: ExecutionContext): any[] {
    if (context.getType() === 'http') {
      const request = context.switchToHttp().getRequest()
      return [request.body, request.params, request.query, request]
    } else if (context.getType() === 'rpc') {
      return context.switchToRpc().getData()
    } else if (context.getType() === 'ws') {
      const data = context.switchToWs().getData()
      return Array.isArray(data) ? data : [data]
    }

    return []
  }

  private getRequest(context: ExecutionContext): Request | undefined {
    // Nếu đã được inject qua constructor
    if (this.request) {
      return this.request
    }

    // Nếu là HTTP request
    if (context.getType() === 'http') {
      return context.switchToHttp().getRequest<Request>()
    }

    return undefined
  }

  private getResponse(context: ExecutionContext): Response | undefined {
    // Nếu là HTTP request
    if (context.getType() === 'http') {
      return context.switchToHttp().getResponse<Response>()
    }

    return undefined
  }

  private buildAuditLogData(
    options: AuditLogOptions,
    args: any[],
    result: any,
    userFromRequest?: AccessTokenPayload,
    req?: Request,
    res?: Response,
    isSuccess: boolean = true,
    error?: any
  ): AuditLogData {
    const startTime = Date.now()
    const auditLogData: AuditLogData = {
      action: isSuccess ? options.action : `${options.action}_FAILED`,
      status: isSuccess ? AuditLogStatus.SUCCESS : AuditLogStatus.FAILURE
    }

    // Lấy userId từ options function hoặc từ request
    if (options.getUserId) {
      auditLogData.userId = options.getUserId(args)
    } else if (userFromRequest?.userId) {
      auditLogData.userId = userFromRequest.userId
    }

    // Lấy userEmail từ options function
    if (options.getUserEmail) {
      auditLogData.userEmail = options.getUserEmail(args)
    }

    // Lấy entity và entityId nếu được định nghĩa
    if (options.entity) {
      auditLogData.entity = options.entity
    }

    if (options.getEntityId && (result || isSuccess === false)) {
      auditLogData.entityId = options.getEntityId(args, result)
    }

    // Lấy details với thông tin context mở rộng
    const details =
      isSuccess && options.getDetails && result
        ? options.getDetails(args, result)
        : !isSuccess && options.getErrorDetails && error
          ? options.getErrorDetails(args, error)
          : {}

    // Thêm thông tin về request context
    if (req) {
      // Lấy route path và method
      const routeDetails = {
        path: req.route?.path,
        method: req.method,
        query: req.query && isObject(req.query) && Object.keys(req.query).length > 0 ? req.query : undefined,
        params: req.params && isObject(req.params) && Object.keys(req.params).length > 0 ? req.params : undefined
      }

      auditLogData.details = {
        ...details,
        request: routeDetails
      }
    } else {
      auditLogData.details = details
    }

    // Lấy notes
    if (isSuccess && options.getNotes && result) {
      auditLogData.notes = options.getNotes(args, result)
    }

    // Xử lý error message
    if (!isSuccess && error) {
      if (options.getErrorMessage) {
        auditLogData.errorMessage = options.getErrorMessage(error)
      } else {
        const normalizedError = normalizeErrorMessage(error)
        auditLogData.errorMessage = normalizedError.message

        // Thêm chi tiết lỗi vào details nếu có
        if (normalizedError.details && auditLogData.details && isObject(auditLogData.details)) {
          // Chuyển đổi ErrorDetailMessage[] sang JsonValue
          const errorDetailsAsJson = JSON.parse(JSON.stringify(normalizedError.details))
          auditLogData.details.errorDetails = errorDetailsAsJson
        }
      }
    }

    // Thêm thông tin từ request
    if (req) {
      auditLogData.ipAddress = req.ip
      auditLogData.userAgent = req.headers['user-agent']
    }

    // Thêm thông tin về thời gian thực thi
    const executionTime = Date.now() - startTime
    if (auditLogData.details && isObject(auditLogData.details)) {
      auditLogData.details.executionTimeMs = executionTime

      // Thêm kích thước phản hồi nếu có
      if (res && typeof res.get === 'function') {
        const contentLength = res.get('content-length')
        if (contentLength) {
          auditLogData.details.responseSize = parseInt(contentLength, 10)
        }
      }
    }

    return auditLogData
  }
}
 