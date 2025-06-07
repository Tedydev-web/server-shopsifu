import { Module, Global, forwardRef } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt'

// Local Imports - Services
import { HashingService } from './services/common/hashing.service'
import { EmailService } from './services/common/email.service'
import { CryptoService } from './services/common/crypto.service'
import { GeolocationService } from './services/common/geolocation.service'
import { CookieService } from './services/common/cookie.service'
import { TokenService } from './services/common/token.service'
import { SLTService } from './services/slt.service'
import { DeviceService } from './services/device.service'
import { UserActivityService } from './services/user-activity.service'
import { UserAgentService } from './services/common/user-agent.service'

// Local Imports - Repositories
import { UserAuthRepository } from './repositories/user-auth.repository'
import { SessionRepository } from './repositories/session.repository'
import { DeviceRepository } from './repositories/device.repository'
import { RecoveryCodeRepository } from './repositories/recovery-code.repository'

// Local Imports - Guards
import { GuardsModule } from './guards/guards.module'

// Injection Tokens
import {
  COOKIE_SERVICE,
  CRYPTO_SERVICE,
  DEVICE_SERVICE,
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  HASHING_SERVICE,
  SLT_SERVICE,
  TOKEN_SERVICE,
  USER_ACTIVITY_SERVICE,
  USER_AGENT_SERVICE
} from 'src/shared/constants/injection.tokens'
import { RedisProviderModule } from 'src/providers/redis/redis.module'

@Global()
@Module({
  imports: [RedisProviderModule, JwtModule.register({}), forwardRef(() => GuardsModule)],
  providers: [
    // Services
    { provide: CRYPTO_SERVICE, useClass: CryptoService },
    UserActivityService,
    { provide: HASHING_SERVICE, useClass: HashingService },
    { provide: EMAIL_SERVICE, useClass: EmailService },
    { provide: GEOLOCATION_SERVICE, useClass: GeolocationService },
    { provide: COOKIE_SERVICE, useClass: CookieService },
    { provide: TOKEN_SERVICE, useClass: TokenService },
    { provide: SLT_SERVICE, useClass: SLTService },
    { provide: DEVICE_SERVICE, useClass: DeviceService },
    { provide: USER_ACTIVITY_SERVICE, useClass: UserActivityService },
    { provide: USER_AGENT_SERVICE, useClass: UserAgentService },
    // Repositories
    UserAuthRepository,
    SessionRepository,
    DeviceRepository,
    RecoveryCodeRepository
  ],
  exports: [
    // Services
    CRYPTO_SERVICE,
    UserActivityService,
    HASHING_SERVICE,
    EMAIL_SERVICE,
    GEOLOCATION_SERVICE,
    COOKIE_SERVICE,
    TOKEN_SERVICE,
    SLT_SERVICE,
    DEVICE_SERVICE,
    USER_ACTIVITY_SERVICE,
    USER_AGENT_SERVICE,
    // Repositories
    UserAuthRepository,
    SessionRepository,
    DeviceRepository,
    RecoveryCodeRepository,
    // Modules
    JwtModule
  ]
})
export class AuthSharedModule {}
