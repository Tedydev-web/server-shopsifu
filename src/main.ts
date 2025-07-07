import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import { Logger } from '@nestjs/common'
import cookieParser from 'cookie-parser'
import { NestExpressApplication } from '@nestjs/platform-express'
import compression from 'compression'
import envConfig from './shared/config'

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule)

  const logger = new Logger('Bootstrap')
  app.useLogger(logger)

  app.enableCors({
    origin: '*'
  })

  app.use(compression())
  app.use(
    cookieParser(envConfig.COOKIE_SECRET, {
      decode: decodeURIComponent
    })
  )

  await app.listen(envConfig.PORT)
}
void bootstrap()
