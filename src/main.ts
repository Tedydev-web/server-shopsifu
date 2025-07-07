import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import { Logger } from '@nestjs/common'
import { NestExpressApplication } from '@nestjs/platform-express'

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule)

  const logger = new Logger('Bootstrap')
  app.useLogger(logger)

  app.enableCors({
    origin: '*'
  })
}
void bootstrap()
