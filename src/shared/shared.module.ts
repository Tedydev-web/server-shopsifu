import { Global, Module } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { HashingService } from './services/hashing.service'
// import { TokenService } from './services/token.service' // Moved
import { JwtModule } from '@nestjs/jwt'
// import { AccessTokenGuard } from 'src/shared/guards/access-token.guard' // Đã di chuyển
import { APIKeyGuard } from 'src/shared/guards/api-key.guard'
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core'
import { AuthenticationGuard } from 'src/shared/guards/authentication.guard'
// import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo' // Đã di chuyển
// import { EmailService } from 'src/shared/services/email.service' // Moved
// import { TwoFactorService } from 'src/shared/services/2fa.service' // Moved
// import { OtpService } from './services/otp.service' // Moved
// import { AuthRepository } from 'src/routes/auth/auth.repo' // Moved to AuthModule
// import { DeviceService } from './services/device.service' // Moved
import { AuditLogInterceptor } from './interceptor/audit-log.interceptor'
// import { TokenRefreshInterceptor } from './interceptor/token-refresh.interceptor' // Đã di chuyển
import { CacheService } from './services/cache.service'
import { AuditLogModule } from 'src/routes/audit-log/audit-log.module'

const sharedServices = [
  PrismaService,
  HashingService,
  // TokenService, // Moved
  // EmailService, // Moved
  // SharedUserRepository, // Keep for now, might be used by other modules --> Đã di chuyển
  // TwoFactorService, // Moved
  // OtpService, // Moved
  // AuthRepository, // Moved to AuthModule
  // DeviceService, // Moved
  CacheService
]

@Global()
@Module({
  providers: [
    ...sharedServices,
    // AccessTokenGuard, // Di chuyển sang AuthModule
    APIKeyGuard,
    {
      provide: APP_GUARD,
      useClass: AuthenticationGuard
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditLogInterceptor
    }
    // TokenRefreshInterceptor đã bị xóa
  ],
  exports: sharedServices,
  imports: [JwtModule, AuditLogModule]
})
export class SharedModule {}
