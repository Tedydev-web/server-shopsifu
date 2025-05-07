import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import compression from 'compression'
import helmet from 'helmet'

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    // logger: ['error', 'warn', 'log', 'debug', 'verbose'],
    logger: ['error', 'warn'],
    cors: {
      origin: '*',
      // origin: ['https://demo-website.live'],
      methods: ['GET', 'POST', 'PUT', 'DELETE']
    }
  })

  // Security
  app.use(helmet())
  app.use(compression())
  // app.use(json({ limit: '10mb' }))

  // Validation
  // app.useGlobalPipes(
  //   new ValidationPipe({
  //     whitelist: true,
  //     transform: true,
  //     forbidNonWhitelisted: true,
  //   }),
  // )

  // Global prefix
  app.setGlobalPrefix('api/v1')

  await app.listen(process.env.PORT ?? 3000)
}
bootstrap()
