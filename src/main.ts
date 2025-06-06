import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import compression from 'compression'
import helmet from 'helmet'
import cookieParser from 'cookie-parser'
import { SecurityHeaders } from './shared/constants/auth.constants'
import { VersioningType, Logger as NestLogger } from '@nestjs/common'
import { NestExpressApplication } from '@nestjs/platform-express'
import { WinstonModule } from 'nest-winston'
import { winstonLogger as winstonLoggerConfig, WinstonConfig } from './shared/logger/winston.config'
import appConfig from './shared/config'

async function bootstrap() {
  const bootstrapLogger = new NestLogger('Bootstrap')
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    logger: WinstonModule.createLogger(WinstonConfig)
  })

  app.enableCors({
    origin: appConfig().FRONTEND_URL,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      SecurityHeaders.XSRF_TOKEN_HEADER,
      SecurityHeaders.CSRF_TOKEN_HEADER
    ],
    exposedHeaders: [SecurityHeaders.XSRF_TOKEN_HEADER, SecurityHeaders.CSRF_TOKEN_HEADER]
  })

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          objectSrc: ["'none'"],
          imgSrc: ["'self'", 'data:'],
          styleSrc: ["'self'"],
          upgradeInsecureRequests: []
        }
      },
      hsts:
        appConfig().NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
      frameguard: { action: 'deny' },
      dnsPrefetchControl: { allow: false },
      noSniff: true,
      xssFilter: true
    })
  )
  app.use(compression())

  app.use(
    cookieParser(appConfig().COOKIE_SECRET, {
      decode: decodeURIComponent
    })
  )

  app.setGlobalPrefix('api/v1', {
    exclude: ['/']
  })

  app.enableVersioning({
    type: VersioningType.URI
  })

  const port = appConfig().PORT ?? 3000
  await app.listen(port)
  winstonLoggerConfig.log(`Application is running on: ${appConfig().API_URL}/api/v1`, 'Bootstrap')
  bootstrapLogger.log(`Swagger documentation available at ${await app.getUrl()}/api-docs`)
}
void bootstrap()
