import { Global, Module } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { HashingService } from './services/hashing.service'
import { TokenService } from './services/token.service'
import { JwtModule } from '@nestjs/jwt'
import { AccessTokenGuard } from 'src/shared/guards/access-token.guard'
import { APIKeyGuard } from 'src/shared/guards/api-key.guard'
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core'
import { AuthenticationGuard } from 'src/shared/guards/authentication.guard'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { EmailService } from 'src/shared/services/email.service'
import { TwoFactorService } from 'src/shared/services/2fa.service'
import { AuditLogService } from './services/audit.service'
import { OtpService } from './services/otp.service'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { DeviceService } from './services/device.service'
import { AuditLogInterceptor } from './interceptor/audit-log.interceptor'
import { TokenRefreshInterceptor } from './interceptor/token-refresh.interceptor'
import { CacheService } from './services/cache.service'

const sharedServices = [
  PrismaService,
  HashingService,
  TokenService,
  EmailService,
  SharedUserRepository,
  TwoFactorService,
  AuditLogService,
  OtpService,
  AuthRepository,
  DeviceService,
  CacheService
]

@Global()
@Module({
  providers: [
    ...sharedServices,
    AccessTokenGuard,
    APIKeyGuard,
    {
      provide: APP_GUARD,
      useClass: AuthenticationGuard
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditLogInterceptor
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: TokenRefreshInterceptor
    }
  ],
  exports: sharedServices,
  imports: [JwtModule]
})
export class SharedModule {}
