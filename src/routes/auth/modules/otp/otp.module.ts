import { forwardRef, Module } from '@nestjs/common'
import { OtpController } from './otp.controller'
import { OtpService } from './otp.service'
import { CoreModule } from '../core/core.module'
import { SessionsModule } from '../sessions/sessions.module'
import { TokenService } from 'src/shared/services/token.service'
import { JwtModule } from '@nestjs/jwt'
import { ConfigModule, ConfigService } from '@nestjs/config'

@Module({
  imports: [
    CoreModule,
    forwardRef(() => SessionsModule),
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
  controllers: [OtpController],
  providers: [OtpService, TokenService],
  exports: [OtpService]
})
export class OtpModule {}
