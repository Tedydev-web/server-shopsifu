import { NestFactory, HttpAdapterHost } from '@nestjs/core'
import { AppModule } from './app.module'
import compression from 'compression'
import helmet from 'helmet'
import cookieParser from 'cookie-parser'
import envConfig from './shared/config'
import { winstonLogger } from './shared/logger/winston.config'
import { AllExceptionsFilter } from './shared/filters/all-exceptions.filter'

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: winstonLogger
  })

  app.enableCors({
    origin: [envConfig.FRONTEND_HOST_URL, envConfig.FRONTEND_LOCAL_URL],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'x-csrf-token']
  })

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          objectSrc: ["'none'"],
          imgSrc: ["'self'", 'data:'],
          styleSrc: ["'self'"]
        }
      },
      hsts: envConfig.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
      frameguard: { action: 'deny' },
      xXssProtection: true,
      noSniff: true
    })
  )
  app.use(compression())

  app.use(
    cookieParser(envConfig.COOKIE_SECRET, {
      decode: decodeURIComponent
    })
  )

  const httpAdapterHost = app.get(HttpAdapterHost)
  app.useGlobalFilters(new AllExceptionsFilter(httpAdapterHost))

  app.setGlobalPrefix('api/v1')

  const port = envConfig.PORT ?? 3000
  await app.listen(port)
  winstonLogger.log(`Application is running on: ${envConfig.API_LOCAL_URL}/api/v1`, 'Bootstrap')
}
void bootstrap()
