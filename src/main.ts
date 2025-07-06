import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import { Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import cookieParser from 'cookie-parser'
import { NestExpressApplication } from '@nestjs/platform-express'
import compression from 'compression'

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule)

  const configService = app.get(ConfigService)

  const logger = new Logger('Bootstrap')
  app.useLogger(logger)

  app.enableCors({
    origin: '*'
  })

  app.use(compression())
  app.use(
    cookieParser(configService.get<string>('cookie.secret'), {
      decode: decodeURIComponent
    })
  )

  await app.listen(configService.get<number>('app.port') ?? 3000)
}
void bootstrap()
