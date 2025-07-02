import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import helmet from 'helmet'
import { Logger, VersioningType } from '@nestjs/common'
import { useContainer } from 'class-validator'
import { CsrfProtectionMiddleware } from './shared/middleware/csrf.middleware'
import { SecurityHeadersMiddleware } from './shared/middleware/security-headers.middleware'
import { ConfigService } from '@nestjs/config'
import cookieParser from 'cookie-parser'
import { NestExpressApplication } from '@nestjs/platform-express'
import compression from 'compression'

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule)

  // app.set('trust proxy', 1)

  const configService = app.get(ConfigService)

  // useContainer(app.select(AppModule), { fallbackOnErrors: true })

  const logger = new Logger('Bootstrap')
  app.useLogger(logger)

  app.enableCors({
    origin: '*',
    // methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    // credentials: true,
    // allowedHeaders: ['Content-Type', 'Authorization', 'X-XSRF-TOKEN', 'X-CSRF-TOKEN'],
    // exposedHeaders: ['X-XSRF-TOKEN', 'X-CSRF-TOKEN'],
  })

  // app.use(
  //   helmet({
  //     contentSecurityPolicy: {
  //       directives: {
  //         defaultSrc: ["'self'"],
  //         scriptSrc: ["'self'", "'unsafe-inline'"],
  //         objectSrc: ["'none'"],
  //         imgSrc: ["'self'", 'data:'],
  //         styleSrc: ["'self'"],
  //         upgradeInsecureRequests: [],
  //       },
  //     },
  //     hsts:
  //       configService.get<string>('app.nodeEnv') === 'production'
  //         ? { maxAge: 31536000, includeSubDomains: true, preload: true }
  //         : false,
  //     frameguard: { action: 'deny' },
  //     dnsPrefetchControl: { allow: false },
  //     noSniff: true,
  //     xssFilter: true,
  //   }),
  // )

  app.use(compression())
  app.use(
    cookieParser(configService.get<string>('cookie.secret'), {
      decode: decodeURIComponent,
    }),
  )

  // const csrfMiddleware = app.get(CsrfProtectionMiddleware)
  // app.use(csrfMiddleware.use.bind(csrfMiddleware))

  // const securityHeadersMiddleware = app.get(SecurityHeadersMiddleware)
  // app.use(securityHeadersMiddleware.use.bind(securityHeadersMiddleware))

  // app.setGlobalPrefix('api/v1', {
  //   exclude: ['/'],
  // })

  // app.enableVersioning({
  //   type: VersioningType.URI,
  // })

  await app.listen(3000)

  logger.log(`🚀 Application is running on: http://localhost:3000`)
}
void bootstrap()
