import { HttpAdapterHost, NestFactory, Reflector } from '@nestjs/core'
import { AppModule } from './app.module'
import compression from 'compression'
import helmet from 'helmet'
import cookieParser from 'cookie-parser'
import { HttpHeader } from './shared/constants/http.constants'
import { VersioningType } from '@nestjs/common'
import CustomZodValidationPipe from './shared/pipes/custom-zod-validation.pipe'
import { NestExpressApplication } from '@nestjs/platform-express'
import { WinstonModule } from 'nest-winston'
import { WinstonConfig, winstonLogger as winstonLoggerConfig } from './shared/logger/winston.config'
import appConfig from './shared/config'
import { RequestIdMiddleware } from './shared/middleware/request-id.middleware'
import { I18nTranslations } from './generated/i18n.generated'

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    logger: WinstonModule.createLogger(WinstonConfig)
  })

  app.set('trust proxy', 1)

  // Apply RequestIdMiddleware to ensure all requests have an ID
  const requestIdMiddleware = new RequestIdMiddleware()
  app.use((req, res, next) => requestIdMiddleware.use(req, res, next))

  app.enableCors({
    origin: appConfig().FRONTEND_URL,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', HttpHeader.XSRF_TOKEN_HEADER, HttpHeader.CSRF_TOKEN_HEADER],
    exposedHeaders: [HttpHeader.XSRF_TOKEN_HEADER, HttpHeader.CSRF_TOKEN_HEADER]
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

  // Use I18nValidationPipe globally
  app.useGlobalPipes(new CustomZodValidationPipe())

  const port = appConfig().PORT ?? 3000
  await app.listen(port)
  winstonLoggerConfig.log(`Application is running on: ${appConfig().API_URL}/api/v1`, 'Bootstrap')
}
void bootstrap()
