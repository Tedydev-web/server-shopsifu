import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { SecurityHeadersMiddleware } from './security-headers.middleware'
import { CsrfMiddleware } from './csrf.middleware'
import { LoggerMiddleware } from './logger.middleware'

@Module({
  imports: [ConfigModule],
  providers: [SecurityHeadersMiddleware, CsrfMiddleware, LoggerMiddleware],
  exports: [SecurityHeadersMiddleware, CsrfMiddleware, LoggerMiddleware]
})
export class MiddlewaresModule {}
