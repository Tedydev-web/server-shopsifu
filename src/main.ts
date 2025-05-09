import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import compression from 'compression'
import helmet from 'helmet'

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log', 'verbose', 'debug']
  })
  app.enableCors({
    origin: '*',
    methods: 'GET,POST,PUT,DELETE',
    credentials: true
  })

  // Security
  app.use(helmet())
  app.use(compression())

  // Global prefix
  app.setGlobalPrefix('api/v1')

  await app.listen(process.env.PORT ?? 3000)
}
bootstrap()
