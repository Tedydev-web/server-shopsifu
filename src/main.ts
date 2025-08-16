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

async function bootstrap(): Promise<void> {
  const server = express()
  server.disable('x-powered-by')
  let app: any

  try {
    // Create app
    app = await NestFactory.create(AppModule, new ExpressAdapter(server), {
      bufferLogs: true
    })

    server.use(bodyParser.json({ limit: '10mb' }))
    server.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }))

    const config = app.get(ConfigService)
    const logger = app.get(Logger)
    const host = config.getOrThrow('app.http.host')
    const port = config.getOrThrow('app.http.port')

    // Middleware (OPTIMIZED FOR PRODUCTION)
    app.use(
      helmet({
        crossOriginResourcePolicy: { policy: 'cross-origin' },
        // Tối ưu security cho production
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
          },
        },
        // Tối ưu performance
        noSniff: true,
        xssFilter: true,
        frameguard: { action: 'deny' }
      })
    )

    // Compression (OPTIMIZED FOR HIGH TRAFFIC)
    app.use(compression({
      threshold: 1024,
      level: 6, // Balance between compression and CPU usage
      filter: (req, res) => {
        if (req.headers['x-no-compression']) {
          return false
        }
        return compression.filter(req, res)
      }
    }))

    app.useLogger(logger)
    app.enableCors(config.get('app.cors'))
    app.use(cookieParser())
    app.set('trust proxy', 'loopback')
    app.enableShutdownHooks()

    // Websocket
    const websocketAdapter = new WebsocketAdapter(app)
    await websocketAdapter.connectToRedis()
    app.useWebSocketAdapter(websocketAdapter)

    // // Global settings
    // app.useGlobalPipes(
    //   new ValidationPipe({
    //     transform: true,
    //     whitelist: true,
    //     forbidNonWhitelisted: true
    //   })
    // )

    // app.enableVersioning({
    //   type: VersioningType.URI,
    //   defaultVersion: '1'
    // })

    // useContainer(app.select(AppModule), { fallbackOnErrors: true })

    // Graceful shutdown
    const gracefulShutdown = async (signal: string) => {
      logger.log(`Received ${signal}, shutting down gracefully...`)

      try {
        // Close WebSocket adapter
        if (websocketAdapter && typeof websocketAdapter.close === 'function') {
          await websocketAdapter.close()
        }

        // Close application
        await app.close()

        logger.log(`✅ Container ${process.pid} closed cleanly. Bye!`)
        process.exit(0)
      } catch (error) {
        logger.error(`❌ Error during shutdown:`, error)
        process.exit(1)
      }
    }

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
    process.on('SIGINT', () => gracefulShutdown('SIGINT'))
    process.on('SIGUSR2', () => gracefulShutdown('SIGUSR2')) // Docker Swarm restart signal

    // Start server
    await app.listen(port, host)

    const appUrl = await app.getUrl()
    logger.log(`🚀 Container ${process.pid} running on: ${appUrl}`)
    logger.log(`📊 Environment: ${config.get('NODE_ENV')}`)
    logger.log(`🔧 Workers: Single container (Docker Swarm managed)`)
    logger.log(`💾 Memory: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB used`)

    // Performance monitoring (OPTIMIZED FOR PRODUCTION)
    setInterval(() => {
      const memUsage = process.memoryUsage()
      logger.log(`📊 Memory Usage - RSS: ${Math.round(memUsage.rss / 1024 / 1024)}MB, Heap: ${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`)
    }, 300000) // Log every 5 minutes

  } catch (error) {
    console.error(`❌ Container ${process.pid} failed to start:`, error)
    process.exit(1)
  }
}

bootstrap()
