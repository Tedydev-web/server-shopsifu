import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common'
import cookieParser from 'cookie-parser'
import envConfig from '../config'

@Module({})
export class CookieParserModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(cookieParser(envConfig.COOKIE_SECRET)).forRoutes('*')
  }
}
