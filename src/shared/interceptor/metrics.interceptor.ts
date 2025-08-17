import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Logger } from '@nestjs/common'
import { Observable } from 'rxjs'
import { tap, catchError } from 'rxjs/operators'
import { throwError } from 'rxjs'
import { MetricsService } from '../services/metrics.service'

/**
 * Simple MetricsInterceptor - Clean and Minimal
 */
@Injectable()
export class MetricsInterceptor implements NestInterceptor {
  private readonly logger = new Logger(MetricsInterceptor.name)

  constructor(private readonly metricsService: MetricsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    if (context.getType() !== 'http') {
      return next.handle()
    }

    const request = context.switchToHttp().getRequest()
    const { method } = request
    const route = this.getRoute(request)
    const startTime = Date.now()

    return next.handle().pipe(
      tap(() => {
        const response = context.switchToHttp().getResponse()
        const duration = (Date.now() - startTime) / 1000
        this.recordMetrics(method, route, response.statusCode, duration)
      }),
      catchError((error) => {
        const statusCode = error.status || 500
        const duration = (Date.now() - startTime) / 1000
        this.recordMetrics(method, route, statusCode, duration)
        return throwError(() => error)
      })
    )
  }

  private recordMetrics(method: string, route: string, statusCode: number, duration: number): void {
    try {
      this.metricsService.incrementHttpRequests(method, route, statusCode)
      this.metricsService.observeHttpRequestDuration(method, route, statusCode, duration)
    } catch (error) {
      this.logger.error('Failed to record metrics:', error)
    }
  }

  private getRoute(request: any): string {
    return request.route?.path || request.url?.split('?')[0] || '/'
  }
}
