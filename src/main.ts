import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import compression from 'compression'
import helmet from 'helmet'
import cookieParser from 'cookie-parser'
import envConfig from './shared/config'

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log', 'verbose', 'debug']
  })

  // Cấu hình CORS để cho phép cookies
  app.enableCors({
    origin: ['https://shopsifu.live', 'http://localhost:8000'], // Cho phép mọi origin trong môi trường dev, thay đổi thành domain thực sự trong production
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true, // Quan trọng cho cookies
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'x-csrf-token']
  })

  // Security
  app.use(helmet())
  app.use(compression())

  // Cookie parser - không ký cookies CSRF để đảm bảo khớp với csurf
  app.use(
    cookieParser(envConfig.COOKIE_SECRET, {
      decode: decodeURIComponent
    })
  )

  // Global prefix
  app.setGlobalPrefix('api/v1')

  await app.listen(process.env.PORT ?? 3000)
}
bootstrap()
