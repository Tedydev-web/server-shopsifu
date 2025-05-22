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
import { AuditLogService, AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { AUDIT_LOG_KEY, AuditLogOptions } from '../decorators/audit-log.decorator'
import { REQUEST } from '@nestjs/core'
import { Request } from 'express'
import { createAuditLog, extractUserFromRequest, CreateAuditLogOptions } from '../utils/audit-log.utils'

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

    const req = this.getRequest(context)
    const { userId: userIdFromToken } = extractUserFromRequest(req)
    const startTime = Date.now()

    return next.handle().pipe(
      tap((result) => {
        const auditLogData = this.buildAuditLogEntry(auditLogOptions, context, result, undefined, userIdFromToken)
        void this.auditLogService.record(auditLogData)
      }),
      catchError((error) => {
        const auditLogData = this.buildAuditLogEntry(auditLogOptions, context, undefined, error, userIdFromToken)
        void this.auditLogService.record(auditLogData)
        throw error
      }),
      finalize(() => {
        const executionTime = Date.now() - startTime
        this.logger.debug(`Method execution completed in ${executionTime}ms`)
      })
    )
  }

  private getRequest(context: ExecutionContext): Request {
    return this.request || context.switchToHttp().getRequest<Request>()
  }

  private buildAuditLogEntry(
    options: AuditLogOptions,
    context: ExecutionContext,
    result?: any,
    error?: any,
    userIdFromToken?: number
  ): AuditLogData {
    const args = this.getArgs(context)
    const req = this.getRequest(context)

    let entityIdFromOptions: string | number | undefined
    if (options.getEntityId) {
      try {
        entityIdFromOptions = options.getEntityId(args, result)
      } catch (e) {
        this.logger.warn(`Error executing getEntityId: ${e.message}`)
      }
    }

    let detailsFromOptions: Record<string, any> | undefined
    if (error && options.getErrorDetails) {
      try {
        detailsFromOptions = options.getErrorDetails(args, error)
      } catch (e) {
        this.logger.warn(`Error executing getErrorDetails: ${e.message}`)
      }
    } else if (!error && options.getDetails && result) {
      try {
        detailsFromOptions = options.getDetails(args, result)
      } catch (e) {
        this.logger.warn(`Error executing getDetails: ${e.message}`)
      }
    }

    let notesFromOptions: string | undefined
    if (!error && options.getNotes && result) {
      try {
        notesFromOptions = options.getNotes(args, result)
      } catch (e) {
        this.logger.warn(`Error executing getNotes: ${e.message}`)
      }
    }

    let userIdFromOptions: number | undefined
    if (options.getUserId) {
      try {
        userIdFromOptions = options.getUserId(args)
      } catch (e) {
        this.logger.warn(`Error executing getUserId: ${e.message}`)
      }
    }

    let errorMessageFromOptions: string | undefined
    if (error && options.getErrorMessage) {
      try {
        errorMessageFromOptions = options.getErrorMessage(error)
      } catch (e) {
        this.logger.warn(`Error executing getErrorMessage: ${e.message}`)
      }
    }

    const auditContext = {
      request: req,
      userId: userIdFromOptions ?? userIdFromToken,
      error,
      result
    }

    const auditOptions: CreateAuditLogOptions = {
      action: options.action,
      entity: options.entity,
      entityId: entityIdFromOptions,
      details: detailsFromOptions,
      errorMessage: errorMessageFromOptions,
      notes: notesFromOptions,
      includeRequest: true,
      includeRequestBody: true // Assuming you want to include request body by default
    }

    return createAuditLog(auditContext, auditOptions)
  }

  private getArgs(context: ExecutionContext): any[] {
    if (context.getType() === 'http') {
      const request = context.switchToHttp().getRequest()
      // Return body, params, query, and the full request object for flexibility in custom functions
      return [request.body, request.params, request.query, request]
    } else if (context.getType() === 'rpc') {
      return context.switchToRpc().getData()
    } else if (context.getType() === 'ws') {
      const data = context.switchToWs().getData()
      return Array.isArray(data) ? data : [data]
    }
    return []
  }
}
