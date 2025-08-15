import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import { ExpressAdapter } from '@nestjs/platform-express'
import cookieParser from 'cookie-parser'
import helmet from 'helmet'
import compression from 'compression'
import { WebsocketAdapter } from './websockets/websocket.adapter'
import express from 'express'
import { Logger } from 'nestjs-pino'
import { ConfigService } from '@nestjs/config'
import bodyParser from 'body-parser'
import cluster from 'cluster'
import { cpus } from 'os'

// ==============================================
// CLUSTER CONFIGURATION
// ==============================================
const NUM_WORKERS = process.env.APP_WORKERS ? parseInt(process.env.APP_WORKERS) : cpus().length

// ==============================================
// WORKER PROCESS FUNCTION
// ==============================================
async function startWorker(): Promise<void> {
  const server = express()
  server.disable('x-powered-by')
  let app: any

  try {
    // Create app
    app = await NestFactory.create(AppModule, new ExpressAdapter(server), {
      bufferLogs: true
    })

    // Body limits
    server.use(bodyParser.json({ limit: '2mb' }))
    server.use(bodyParser.urlencoded({ extended: true, limit: '2mb' }))

    const config = app.get(ConfigService)
    const logger = app.get(Logger)
    const host = config.getOrThrow('app.http.host')
    const port = config.getOrThrow('app.http.port')

    // Middleware
    app.use(
      helmet({
        crossOriginResourcePolicy: { policy: 'cross-origin' }
      })
    )
    app.use(compression({ threshold: 1024 }))
    app.useLogger(logger)
    app.enableCors(config.get('app.cors'))
    app.use(cookieParser())
    app.set('trust proxy', 'loopback')
    app.enableShutdownHooks()

    // Websocket
    const websocketAdapter = new WebsocketAdapter(app)
    await websocketAdapter.connectToRedis()
    app.useWebSocketAdapter(websocketAdapter)

    // Graceful shutdown
    const gracefulShutdown = async (signal: string) => {
      logger.log(`Worker ${process.pid} received ${signal}, shutting down gracefully...`)

      // Close WebSocket adapter
      const websocketAdapter = app.get(WebsocketAdapter)
      if (websocketAdapter && typeof websocketAdapter.close === 'function') {
        await websocketAdapter.close()
      }

      await app.close()
      logger.log(`✅ Worker ${process.pid} closed cleanly. Bye!`)
      process.exit(0)
    }

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
    process.on('SIGINT', () => gracefulShutdown('SIGINT'))

    // Start server
    await app.listen(port, host)
    if (typeof process.send === 'function') {
      try {
        process.send('ready')
      } catch {}
    }

    const appUrl = await app.getUrl()
    logger.log(`🚀 Worker ${process.pid} running on: ${appUrl}`)
  } catch (error) {
    console.error(`❌ Worker ${process.pid} failed to start:`, error)
    if (app) await app.close()
    process.exit(1)
  }
}

// ==============================================
// MASTER PROCESS FUNCTION
// ==============================================
function startMaster(): void {
  console.log(`🚀 Master process ${process.pid} starting ${NUM_WORKERS} workers...`)

  // Fork workers
  for (let i = 0; i < NUM_WORKERS; i++) {
    const worker = cluster.fork()

    worker.on('message', (message) => {
      if (message === 'ready') {
        console.log(`✅ Worker ${worker.process.pid} is ready`)
      }
    })

    worker.on('exit', (code, signal) => {
      if (signal) {
        console.log(`⚠️ Worker ${worker.process.pid} was killed by signal: ${signal}`)
      } else if (code !== 0) {
        console.log(`❌ Worker ${worker.process.pid} exited with error code: ${code}`)
      } else {
        console.log(`✅ Worker ${worker.process.pid} exited successfully`)
      }

      // Restart worker if it crashes
      if (code !== 0) {
        console.log(`🔄 Restarting worker...`)
        const newWorker = cluster.fork()

        newWorker.on('message', (message) => {
          if (message === 'ready') {
            console.log(`✅ New worker ${newWorker.process.pid} is ready`)
          }
        })
      }
    })
  }

  // Handle master process shutdown
  const gracefulShutdown = async (signal: string) => {
    console.log(`\n🛑 Master process ${process.pid} received ${signal}, shutting down workers...`)

    // Send SIGTERM to all workers
    for (const id in cluster.workers) {
      const worker = cluster.workers[id]
      if (worker) {
        worker.send('shutdown')
        worker.kill('SIGTERM')
      }
    }

    // Wait for workers to finish
    setTimeout(() => {
      console.log('⏰ Force killing remaining workers...')
      for (const id in cluster.workers) {
        const worker = cluster.workers[id]
        if (worker) {
          worker.kill('SIGKILL')
        }
      }
      process.exit(0)
    }, 10000)

    process.exit(0)
  }

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
  process.on('SIGINT', () => gracefulShutdown('SIGINT'))

  // Monitor workers
  cluster.on('exit', (worker, code, signal) => {
    console.log(`📊 Worker ${worker.process.pid} died. Code: ${code}, Signal: ${signal}`)
  })
}

// ==============================================
// BOOTSTRAP FUNCTION
// ==============================================
async function bootstrap(): Promise<void> {
  if (cluster.isPrimary) {
    startMaster()
  } else {
    await startWorker()
  }
}

bootstrap()
