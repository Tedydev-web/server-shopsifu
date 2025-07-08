import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import { NestExpressApplication } from '@nestjs/platform-express'
import { UPLOAD_DIR } from 'src/shared/constants/other.constant'
import cookieParser from 'cookie-parser'
import session from 'express-session'

import envConfig from 'src/shared/config'
import { COOKIE_DEFINITIONS } from './shared/constants/cookie.constant'

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule)

  // CORS configuration
  app.enableCors({
    origin:
      process.env.NODE_ENV === 'production'
        ? ['https://yourdomain.com'] // Thay đổi domain production
        : ['http://localhost:3000', 'http://localhost:3001'],
    credentials: true, // Quan trọng cho cookies
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-XSRF-Token']
  })

  // Cookie parser middleware
  app.use(cookieParser(envConfig.COOKIE_SECRET))

  // Session middleware (cần thiết cho CSRF)
  app.use(
    session({
      name: COOKIE_DEFINITIONS.session.name,
      secret: envConfig.COOKIE_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: COOKIE_DEFINITIONS.session.options
    })
  )

  // app.useStaticAssets(UPLOAD_DIR, {
  //   prefix: '/media/static',
  // })

  await app.listen(process.env.PORT ?? 3000)
}
bootstrap()
