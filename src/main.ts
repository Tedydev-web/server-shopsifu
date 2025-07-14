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

async function bootstrap(): Promise<void> {
  const server = express()
  let app: any

  try {
    // Create app
    app = await NestFactory.create(AppModule, new ExpressAdapter(server), {
      bufferLogs: true
    })

    const config = app.get(ConfigService)
    const logger = app.get(Logger)
    const host = config.getOrThrow('app.http.host')
    const port = config.getOrThrow('app.http.port')

    // Middleware
    app.use(helmet())
    app.use(compression())
    app.useLogger(logger)
    app.enableCors(config.getOrThrow('app.cors'))
    app.set('trust proxy', 'loopback') // Trust requests from the loopback address

    // Websocket
    const websocketAdapter = new WebsocketAdapter(app)
    await websocketAdapter.connectToRedis()
    app.useWebSocketAdapter(websocketAdapter)

    // Cookie parser middleware
    app.use(cookieParser())

    // app.enableVersioning({
    //   type: VersioningType.URI,
    //   defaultVersion: '1'
    // })

    // Graceful shutdown
    const gracefulShutdown = async (signal: string) => {
      logger.log(`Received ${signal}, shutting down gracefully...`)
      await app.close()
      process.exit(0)
    }

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
    process.on('SIGINT', () => gracefulShutdown('SIGINT'))

    // Start server
    await app.listen(port, host)

    const appUrl = await app.getUrl()
    logger.log(`🚀 Server running on: ${appUrl}`)
  } catch (error) {
    console.error('❌ Server failed to start:', error)
    if (app) await app.close()
    process.exit(1)
  }
}

bootstrap()
