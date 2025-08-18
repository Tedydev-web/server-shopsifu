import http from 'http'
import os from 'os'
import cluster from 'cluster'
import type { Express } from 'express'
import client, { Counter, Gauge, Histogram, collectDefaultMetrics } from 'prom-client'

// Thu thập default metrics của Node.js
collectDefaultMetrics({ prefix: 'node_', timeout: 5000 })

// Histogram latency HTTP theo Golden Signals
export const httpServerDurationSeconds: Histogram<string> = new client.Histogram({
  name: 'http_server_duration_seconds',
  help: 'API latency',
  labelNames: ['method', 'route', 'status_code', 'service', 'env', 'version', 'instance', 'worker'],
  buckets: [0.01, 0.025, 0.05, 0.1, 0.2, 0.4, 0.8, 1.5, 3]
})

// Số request tổng, phục vụ tính Availability/Errors/Throughput
export const httpServerRequestsTotal: Counter<string> = new client.Counter({
  name: 'http_server_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status_code', 'service', 'env', 'version', 'instance', 'worker']
})

// In-flight requests
export const httpServerInflight: Gauge<string> = new client.Gauge({
  name: 'http_server_inflight_requests',
  help: 'Concurrent in-flight',
  labelNames: ['service', 'instance', 'worker']
})

export type MetricsMeta = {
  service: string
  env: string
  version: string
  instance: string
  worker: string
}

export function wrapExpressForMetrics(app: Express, metaInput?: Partial<MetricsMeta>): void {
  const meta: MetricsMeta = {
    service: process.env.SERVICE || 'api',
    env: process.env.NODE_ENV || 'dev',
    version: process.env.APP_VERSION || 'dev',
    instance: process.env.INSTANCE || os.hostname(),
    worker: process.env.INSTANCE_ID || process.env.PM2_INSTANCE_ID || (process.env.NODE_APP_INSTANCE ?? '0'),
    ...metaInput
  }

  app.use((req, res, next) => {
    httpServerInflight.inc({ service: meta.service, instance: meta.instance, worker: meta.worker })
    const endTimer = httpServerDurationSeconds.startTimer({
      method: req.method,
      route: (req as any).route?.path || (req as any).path || 'unknown',
      service: meta.service,
      env: meta.env,
      version: meta.version,
      instance: meta.instance,
      worker: meta.worker
    })

    res.on('finish', () => {
      const statusCode = String(res.statusCode)
      endTimer({ status_code: statusCode })
      httpServerRequestsTotal.inc({
        method: req.method,
        route: (req as any).route?.path || (req as any).path || 'unknown',
        status_code: statusCode,
        service: meta.service,
        env: meta.env,
        version: meta.version,
        instance: meta.instance,
        worker: meta.worker
      })
      httpServerInflight.dec({ service: meta.service, instance: meta.instance, worker: meta.worker })
    })

    next()
  })
}

export function serveMetrics(basePort?: number, metaInput?: Partial<MetricsMeta>): void {
  let computedWorkerId: number | null = null
  const envWorker = process.env.INSTANCE_ID || process.env.PM2_INSTANCE_ID || process.env.NODE_APP_INSTANCE
  if (envWorker && /^\d+$/.test(envWorker)) {
    computedWorkerId = Number(envWorker)
  } else if (cluster && (cluster as any).worker && (cluster as any).worker.id) {
    // PM2 cluster: id starts at 1 → dùng (id-1)
    computedWorkerId = Math.max(0, Number((cluster as any).worker.id) - 1)
  } else {
    computedWorkerId = 0
  }
  const workerId = computedWorkerId
  const portBase = Number(basePort ?? process.env.METRICS_BASE_PORT ?? 9200)
  const port = portBase + workerId

  const server = http.createServer(async (req, res) => {
    if (req.url === '/metrics') {
      try {
        res.writeHead(200, { 'Content-Type': client.register.contentType })
        res.end(await client.register.metrics())
      } catch (err) {
        res.writeHead(500)
        res.end('metrics_error')
      }
    } else {
      res.writeHead(404)
      res.end()
    }
  })

  // Mặc định bind 0.0.0.0 để Prometheus trong Docker có thể scrape qua host.docker.internal
  server.listen(port, '0.0.0.0')
}

export const metricsClient = client
