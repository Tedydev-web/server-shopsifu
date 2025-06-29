import { Module, forwardRef } from '@nestjs/common'
import { AuthController } from './controllers/auth.controller'
import { CoreAuthService } from './services/core.service'
import { RolesService } from './services/roles.service'
import { SharedRoleRepository } from 'src/shared/repositories/shared-role.repo'
import { GoogleService } from './services/social/google.service'
import { DeviceModule } from '../device/device.module'
import { SessionRepository } from './repositories/session.repository'
import { OtpService } from './services/otp.service'
import { VerificationCodeRepository } from './repositories/verification-code.repository'
import { PasswordService } from './services/password.service'
import { SessionService } from './services/session.service'

@Module({
  imports: [DeviceModule],
  controllers: [AuthController],
  providers: [
    CoreAuthService,
    RolesService,
    SharedRoleRepository,
    GoogleService,
    SessionRepository,
    OtpService,
    VerificationCodeRepository,
    PasswordService,
    SessionService,
  ],
  exports: [CoreAuthService, SessionService],
})
export class AuthModule {}
