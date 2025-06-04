import { forwardRef, Module } from '@nestjs/common'
import { SessionsController } from './sessions.controller'
import { SessionsService } from './sessions.service'
import { SharedModule } from 'src/shared/shared.module'
import { OtpModule } from '../otp/otp.module'
import { CookieService } from '../../shared/cookie/cookie.service'
import { EmailService } from 'src/shared/services/email.service'
import { EMAIL_SERVICE } from 'src/shared/constants/injection.tokens'
import { DeviceRepository } from '../../repositories/device.repository'
import { SessionRepository } from '../../repositories/session.repository'
import { TokenService } from '../../shared/token/token.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { UserAuthRepository } from '../../repositories/user-auth.repository'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'
import { RedisProviderModule } from 'src/shared/providers/redis/redis.module'

@Module({
  imports: [
    SharedModule,
    forwardRef(() => OtpModule),
    RedisProviderModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET') || 'SECRET',
        signOptions: {
          expiresIn: configService.get<string>('JWT_ACCESS_EXPIRATION', '1h')
        }
      })
    })
  ],
  controllers: [SessionsController],
  providers: [
    SessionsService,
    SessionRepository,
    DeviceRepository,
    TokenService,
    PrismaService,
    UserAuthRepository,
    GeolocationService,
    {
      provide: EMAIL_SERVICE,
      useClass: EmailService
    },
    CookieService
  ],
  exports: [SessionsService]
})
export class SessionsModule {}
