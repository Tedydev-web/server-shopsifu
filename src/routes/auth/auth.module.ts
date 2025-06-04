import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'
import { CoreModule } from './modules/core/core.module'
import { SessionsModule } from './modules/sessions/sessions.module'
import { OtpModule } from './modules/otp/otp.module'
import { SocialModule } from './modules/social/social.module'
import { TwoFactorModule } from './modules/two-factor/two-factor.module'
// Các Repositories và Services sẽ được cung cấp bởi SharedModule (global)
// TokenRefreshInterceptor sẽ được chuyển sang SharedModule hoặc InterceptorsModule

@Module({
  imports: [
    ConfigModule, // ConfigModule có thể cần thiết nếu AuthModule có cấu hình riêng
    JwtModule, // JwtModule có thể cần nếu AuthModule trực tiếp sử dụng JWT operations, nhưng thường các sub-modules sẽ import nếu cần
    CoreModule,
    SessionsModule,
    OtpModule,
    SocialModule,
    TwoFactorModule
  ],
  providers: [
    // Không cung cấp lại services/repositories đã có ở SharedModule
    // TokenRefreshInterceptor sẽ được chuyển đi
  ],
  exports: [
    // AuthModule không cần export các shared components này nữa
  ]
})
export class AuthModule {}
