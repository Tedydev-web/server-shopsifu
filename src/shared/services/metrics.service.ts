import { Injectable, OnModuleInit, Logger } from '@nestjs/common'
import { collectDefaultMetrics, register, Counter, Histogram } from 'prom-client'

/**
 * Simple MetricsService - Only Essential Metrics
 */
@Injectable()
export class MetricsService implements OnModuleInit {
  private readonly logger = new Logger(MetricsService.name)

  // Core metrics only
  private readonly httpRequestsTotal: Counter<string>
  private readonly httpRequestDuration: Histogram<string>

  constructor() {
    // Initialize core metrics
    this.httpRequestsTotal = new Counter({
      name: 'shopsifu_http_requests_total',
      help: 'Total HTTP requests',
      labelNames: ['method', 'route', 'status_code']
    })

    this.httpRequestDuration = new Histogram({
      name: 'shopsifu_http_request_duration_seconds',
      help: 'HTTP request duration in seconds',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [0.1, 0.5, 1, 2, 5]
    })
  }

  onModuleInit() {
    try {
      // Collect default Node.js metrics
      collectDefaultMetrics({ prefix: 'shopsifu_' })
      this.logger.log('Metrics service initialized')
    } catch (error) {
      this.logger.error('Failed to initialize metrics:', error)
    }
  }

  async getMetrics(): Promise<string> {
    return register.metrics()
  }

  // Core methods
  incrementHttpRequests(method: string, route: string, statusCode: number): void {
    this.httpRequestsTotal.inc({ method, route, status_code: statusCode.toString() })
  }

  observeHttpRequestDuration(method: string, route: string, statusCode: number, duration: number): void {
    this.httpRequestDuration.observe({ method, route, status_code: statusCode.toString() }, duration)
  }
}
