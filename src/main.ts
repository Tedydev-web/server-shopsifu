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

    // Body limits
    server.use(bodyParser.json({ limit: '2mb' }))
    server.use(bodyParser.urlencoded({ extended: true, limit: '2mb' }))

    const config = app.get(ConfigService)
    const logger = app.get(Logger)
    const host = config.getOrThrow('app.http.host')
    const port = config.getOrThrow('app.http.port')

    // Middleware
    app.use(helmet({
      crossOriginResourcePolicy: { policy: 'cross-origin' }
    }))
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

      // Close WebSocket adapter
      const websocketAdapter = app.get(WebsocketAdapter)
      if (websocketAdapter && typeof websocketAdapter.close === 'function') {
        await websocketAdapter.close()
      }

      await app.close()
      logger.log('✅ Application closed cleanly. Bye!')
      process.exit(0)
    }

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
    process.on('SIGINT', () => gracefulShutdown('SIGINT'))

    // Start server
    await app.listen(port, host)
    if (typeof process.send === 'function') {
      try { process.send('ready') } catch {}
    }

    const appUrl = await app.getUrl()
    logger.log(`🚀 Server running on: ${appUrl}`)
  } catch (error) {
    console.error('❌ Server failed to start:', error)
    if (app) await app.close()
    process.exit(1)
  }
}

bootstrap()
