import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import { NestExpressApplication } from '@nestjs/platform-express'
import cookieParser from 'cookie-parser'
import session from 'express-session'
import envConfig from 'src/shared/config'
import { COOKIE_DEFINITIONS } from './shared/constants/cookie.constant'
import helmet from 'helmet'
import compression from 'compression'
import { WebsocketAdapter } from './websockets/websocket.adapter'
import { LoggingInterceptor } from './shared/interceptor/logging.interceptor'
import { ConsoleLogger, Logger } from '@nestjs/common'

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bufferLogs: true })
  app.useLogger(app.get(Logger))
  app.use(helmet())
  app.use(compression())
  // app.useGlobalInterceptors(new LoggingInterceptor())

  const websocketAdapter = new WebsocketAdapter(app)
  await websocketAdapter.connectToRedis()
  app.useWebSocketAdapter(websocketAdapter)

  // CORS configuration
  app.enableCors({
    origin: ['https://localhost:8000', 'https://shopsifu.live'],
    credentials: true, // Quan trọng cho cookies
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-XSRF-Token', 'x-csrf-token', 'x-xsrf-token']
  })

  // Cookie parser middleware
  app.use(cookieParser(envConfig.COOKIE_SECRET))

  // Session middleware
  app.use(
    session({
      name: COOKIE_DEFINITIONS.session.name,
      secret: envConfig.COOKIE_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: COOKIE_DEFINITIONS.session.options
    })
  )

  await app.listen(process.env.PORT ?? 3000)
}
bootstrap()
