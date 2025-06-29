import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import helmet from 'helmet'
import { Logger, VersioningType } from '@nestjs/common'
import { AllExceptionsFilter } from 'src/shared/filters/all-exceptions.filter'
import { I18nService, I18nValidationExceptionFilter } from 'nestjs-i18n'
import { useContainer } from 'class-validator'
import { TransformInterceptor } from 'src/shared/interceptor/transform.interceptor'
import { CsrfProtectionMiddleware } from './shared/middleware/csrf.middleware'
import { SecurityHeadersMiddleware } from './shared/middleware/security-headers.middleware'
import { ConfigService } from '@nestjs/config'
import cookieParser from 'cookie-parser'
import { NestExpressApplication } from '@nestjs/platform-express'
import compression from 'compression'
import CustomZodValidationPipe from './shared/pipes/custom-zod-validation.pipe'

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule)

  app.set('trust proxy', 1)

  const configService = app.get(ConfigService)

  const i18nService = app.get<I18nService<Record<string, unknown>>>(I18nService)

  useContainer(app.select(AppModule), { fallbackOnErrors: true })

  const logger = new Logger('Bootstrap')
  app.useLogger(logger)

  app.enableCors({
    origin: configService.get('app.clientUrl'),
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-XSRF-TOKEN', 'X-CSRF-TOKEN'],
    exposedHeaders: ['X-XSRF-TOKEN', 'X-CSRF-TOKEN'],
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
          upgradeInsecureRequests: [],
        },
      },
      hsts:
        configService.get<string>('app.nodeEnv') === 'production'
          ? { maxAge: 31536000, includeSubDomains: true, preload: true }
          : false,
      frameguard: { action: 'deny' },
      dnsPrefetchControl: { allow: false },
      noSniff: true,
      xssFilter: true,
    }),
  )

  app.use(compression())
  app.use(
    cookieParser(configService.get<string>('cookie.secret'), {
      decode: decodeURIComponent,
    }),
  )

  // app.setGlobalPrefix('api/v1', {
  //   exclude: ['/'],
  // })

  const csrfMiddleware = app.get(CsrfProtectionMiddleware)
  app.use(csrfMiddleware.use.bind(csrfMiddleware))

  const securityHeadersMiddleware = app.get(SecurityHeadersMiddleware)
  app.use(securityHeadersMiddleware.use.bind(securityHeadersMiddleware))

  app.useGlobalInterceptors(new TransformInterceptor(i18nService))

  app.useGlobalFilters(
    new AllExceptionsFilter(i18nService),
    new I18nValidationExceptionFilter({ detailedErrors: false }),
  )

  app.setGlobalPrefix('api/v1', {
    exclude: ['/'],
  })

  app.enableVersioning({
    type: VersioningType.URI,
  })

  app.useGlobalPipes(new CustomZodValidationPipe())

  const port = configService.get<number>('app.port') || 3000
  await app.listen(port)
  logger.log(`🚀 Application is running on: http://localhost:${port}`)
}
void bootstrap()
