import { Global, Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'

// Import services, repositories, guards
import { CookieService } from './services/cookie.service'
import { DeviceService } from './services/device.service'
import { EmailService } from './services/email.service'
import { GeolocationService } from './services/geolocation.service'
import { HashingService } from './services/hashing.service'
import { PrismaService } from './services/prisma.service'
import { SLTService } from './services/slt.service'
import { TokenService } from './services/token.service'
import { UserActivityService } from './services/user-activity.service'
import { UserAgentService } from './services/user-agent.service'

import { DeviceRepository } from './repositories/auth/device.repository'
import { RecoveryCodeRepository } from './repositories/auth/recovery-code.repository'
import { SessionRepository } from './repositories/auth/session.repository'
import { UserAuthRepository } from './repositories/auth/user-auth.repository'

import { ApiKeyGuard } from './guards/api-key.guard'
import { AuthenticationGuard } from './guards/authentication.guard'
import { BasicAuthGuard } from './guards/basic-auth.guard'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { RolesGuard } from './guards/roles.guard'
import { ThrottlerProxyGuard } from './guards/throttler-proxy.guard'

// Import injection tokens
import {
  COOKIE_SERVICE,
  DEVICE_SERVICE, // Added DEVICE_SERVICE token import
  EMAIL_SERVICE,
  GEOLOCATION_SERVICE,
  HASHING_SERVICE,
  SLT_SERVICE,
  TOKEN_SERVICE,
  USER_AGENT_SERVICE
} from './constants/injection.tokens'

const serviceClasses = [
  PrismaService,
  CookieService,
  DeviceService,
  EmailService,
  GeolocationService,
  HashingService,
  SLTService,
  TokenService,
  UserActivityService,
  UserAgentService // No trailing comma here
]

const repositoryClasses = [
  DeviceRepository,
  RecoveryCodeRepository,
  SessionRepository,
  UserAuthRepository // No trailing comma here
]

const guardClasses = [
  ApiKeyGuard,
  AuthenticationGuard,
  BasicAuthGuard,
  JwtAuthGuard,
  RolesGuard,
  ThrottlerProxyGuard // No trailing comma here
]

// Providers for services injected via token
const tokenProviders = [
  { provide: COOKIE_SERVICE, useClass: CookieService },
  { provide: DEVICE_SERVICE, useClass: DeviceService }, // Added DEVICE_SERVICE provider
  { provide: EMAIL_SERVICE, useClass: EmailService },
  { provide: GEOLOCATION_SERVICE, useClass: GeolocationService },
  { provide: HASHING_SERVICE, useClass: HashingService },
  { provide: SLT_SERVICE, useClass: SLTService },
  { provide: TOKEN_SERVICE, useClass: TokenService },
  { provide: USER_AGENT_SERVICE, useClass: UserAgentService }
]

const allProviders = [
  ...serviceClasses,
  ...repositoryClasses,
  ...guardClasses,
  ...tokenProviders // No trailing comma here
]

// Exports include all concrete classes and the token providers
const allExports = [...serviceClasses, ...repositoryClasses, ...guardClasses, ...tokenProviders]

@Global()
@Module({
  imports: [ConfigModule, JwtModule],
  providers: allProviders,
  exports: allExports
})
export class SharedModule {}
