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

  // Cấu hình CORS để cho phép cookies
  app.enableCors({
    origin: ['https://shopsifu.live', 'http://localhost:8000'], // Cho phép mọi origin trong môi trường dev, thay đổi thành domain thực sự trong production
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true, // Quan trọng cho cookies
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'x-csrf-token']
  })

  // Security
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          objectSrc: ["'none'"],
          imgSrc: ["'self'", 'data:'],
          styleSrc: ["'self'"]
          // Thêm các directives khác nếu cần
        }
      },
      hsts: envConfig.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
      frameguard: { action: 'deny' },
      xXssProtection: true, // Tương đương với 1; mode=block
      noSniff: true
      // Các cấu hình khác của helmet có thể giữ mặc định hoặc tùy chỉnh
    })
  )
  app.use(compression())

  // Cookie parser - không ký cookies CSRF để đảm bảo khớp với csurf
  app.use(
    cookieParser(envConfig.COOKIE_SECRET, {
      decode: decodeURIComponent
    })
  )

  // Đăng ký Global Exception Filter mới
  const httpAdapterHost = app.get(HttpAdapterHost)
  app.useGlobalFilters(new AllExceptionsFilter(httpAdapterHost))

  // Global prefix
  app.setGlobalPrefix('api/v1')

  const port = process.env.PORT ?? 3000
  await app.listen(port)
  winstonLogger.log(`Application is running on: http://localhost:${port}/api/v1`, 'Bootstrap')
}
bootstrap()
